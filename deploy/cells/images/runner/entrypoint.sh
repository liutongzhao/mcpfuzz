#!/bin/sh
# runner 容器入口：先把本批清单灌进网关并产出 targets.txt，再调 mcpfuzz 跑批量扫描。
# 扫描本身负责「检测时才上线(enable)→等就绪(tools>0)→扫→停用(disable)」+ 断点续跑(--resume)。
# 容器 restart 时 provision 幂等跳过、scan 自动从断点账本续跑。
set -eu

: "${BATCH:?必须设置 BATCH（批次名）}"
GATEWAY_URL="${GATEWAY_URL:-http://gateway:3000}"
GW_USER="${GATEWAY_USER:-admin}"
GW_PASS="${GATEWAY_PASSWORD:-admin123}"

mkdir -p /work/runs

# 结果属主跟随宿主用户：容器默认 root 写产物 → 宿主普通用户删/改不动 results/。
# 以 root 启动时，取批次清单(宿主用户上传的文件)的 uid:gid（可用 RUN_AS=uid:gid 覆盖），
# 把已有产物(含历史 root 遗留)改回该属主，再降权成该用户重新执行本脚本。
if [ "$(id -u)" = 0 ] && [ -z "${_CELL_DROPPED:-}" ]; then
  RUN_AS="${RUN_AS:-$(stat -c '%u:%g' /work/batch.jsonl)}"
  if [ "${RUN_AS%%:*}" != 0 ]; then
    find /work/runs \( ! -user "${RUN_AS%%:*}" -o ! -group "${RUN_AS##*:}" \) -exec chown -h "$RUN_AS" {} +
    chmod 1777 /work   # provision 要在 /work 下写 targets.txt / bearer.txt
    echo "[cell:$BATCH] 以宿主属主 $RUN_AS 运行（结果文件归宿主用户）"
    export _CELL_DROPPED=1 HOME=/tmp
    exec setpriv --reuid="${RUN_AS%%:*}" --regid="${RUN_AS##*:}" --clear-groups "$0" "$@"
  fi
fi

echo "[cell:$BATCH] 1/2 灌清单进网关 + 部署校验 …"
python3 /app/provision.py \
  --batch /work/batch.jsonl \
  --gateway "$GATEWAY_URL" \
  --user "$GW_USER" \
  --password "$GW_PASS" \
  --targets-out /work/targets.txt \
  --map-out /work/runs/namemap.json \
  --bearer-out /work/bearer.txt

BEARER="$(cat /work/bearer.txt 2>/dev/null || true)"

echo "[cell:$BATCH] 2/2 开始批量扫描 …"
set -- scan \
  --batch /work/targets.txt --batch-name "$BATCH" \
  --gateway "$GATEWAY_URL" \
  --gateway-user "$GW_USER" --gateway-password "$GW_PASS" \
  --gateway-reset before --resume --yes \
  -o /work/runs
# MCP 端点默认需 Bearer 鉴权：带上 provision 铸好的 key（没有则不带，靠网关免鉴权配置）
if [ -n "$BEARER" ]; then
  set -- "$@" --header "Authorization: Bearer $BEARER"
fi

# 单工具总时长看门狗：默认用镜像内置的 900s（15 分钟）；设了 TOOL_TIMEOUT 才覆盖，
# 这样正式批想调阈值不必重打镜像，在 .env 里设 TOOL_TIMEOUT 即可（<=0 关闭看门狗）。
if [ -n "${TOOL_TIMEOUT:-}" ]; then
  set -- "$@" --tool-timeout "$TOOL_TIMEOUT"
fi

exec python3 -m mcpfuzz.cli.main "$@"
