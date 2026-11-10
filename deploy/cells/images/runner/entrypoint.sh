#!/bin/sh
# runner 容器入口（全网大规模批量专用）：
#   1) provision：清空本 cell 网关、铸 bearer key、产出 targets.txt 与 namemap.json（含每个目标的启动命令）。
#      不预先注册任何后端——mcphub 一注册就启动后端，批量预注册会把网关压垮/弄崩（2026-11-10 实测）。
#   2) scan：带 --gateway-launch-map，扫描器对每个目标「临时注册 → 等就绪 → 扫 → 删除」，
#      网关里任何时刻只有当前这一个后端。数据集扫描不走这里，仍是预注册后端 enable/disable。
# 账本 _done.jsonl + --resume 支持断点续跑；整批跑完后对部署失败的目标自动补跑一轮。
set -eu

: "${BATCH:?必须设置 BATCH（批次名）}"
GATEWAY_URL="${GATEWAY_URL:-http://gateway:3000}"
GW_USER="${GATEWAY_USER:-admin}"
GW_PASS="${GATEWAY_PASSWORD:-admin123}"

mkdir -p /work/runs

# —— 结果属主跟随宿主用户：以批次清单(宿主用户上传)的 uid:gid 降权运行，产物归宿主用户 ——
if [ "$(id -u)" = 0 ] && [ -z "${_CELL_DROPPED:-}" ]; then
  RUN_AS="${RUN_AS:-$(stat -c '%u:%g' /work/batch.jsonl)}"
  if [ "${RUN_AS%%:*}" != 0 ]; then
    find /work/runs \( ! -user "${RUN_AS%%:*}" -o ! -group "${RUN_AS##*:}" \) -exec chown -h "$RUN_AS" {} +
    chmod 1777 /work
    echo "[cell:$BATCH] 以宿主属主 $RUN_AS 运行（结果文件归宿主用户）"
    export _CELL_DROPPED=1 HOME=/tmp
    exec setpriv --reuid="${RUN_AS%%:*}" --regid="${RUN_AS##*:}" --clear-groups "$0" "$@"
  fi
fi

echo "[cell:$BATCH] 1/2 provision：清空网关 + 铸 key + 生成目标与启动命令表 …"
python3 /app/provision.py \
  --batch /work/batch.jsonl \
  --gateway "$GATEWAY_URL" \
  --user "$GW_USER" \
  --password "$GW_PASS" \
  --targets-out /work/targets.txt \
  --map-out /work/runs/namemap.json \
  --bearer-out /work/bearer.txt

BEARER="$(cat /work/bearer.txt 2>/dev/null || true)"

echo "[cell:$BATCH] 2/2 开始批量扫描（逐个临时注册 → 扫 → 删除）…"
set -- scan \
  --batch /work/targets.txt --batch-name "$BATCH" \
  --gateway "$GATEWAY_URL" \
  --gateway-user "$GW_USER" --gateway-password "$GW_PASS" \
  --gateway-launch-map /work/runs/namemap.json \
  --resume --yes \
  -o /work/runs
if [ -n "$BEARER" ]; then
  set -- "$@" --header "Authorization: Bearer $BEARER"
fi
# 单工具总时长看门狗：默认镜像内置 900s；设了 TOOL_TIMEOUT 才覆盖（<=0 关闭）
if [ -n "${TOOL_TIMEOUT:-}" ]; then
  set -- "$@" --tool-timeout "$TOOL_TIMEOUT"
fi

exec python3 -m mcpfuzz.cli.main "$@"
