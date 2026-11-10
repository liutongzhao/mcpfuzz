#!/bin/sh
# runner 容器入口：把本批清单【分片】灌进网关并扫描。
#
# 为什么分片：mcphub 网关内存随注册后端数增长，一次灌整批(~539)会涨到 mem_limit → OOM 反复重启
# （2026-11-10 实测网关重启 140+ 次、runner 大面积连接失败、84% 目标被误判失败）。测试批 5 个后端时零重启。
# 分片轮转：每片 SHARD_SIZE 个，provision(reset 清空网关、只留本片)→scan 本片→清空→下一片，
# 网关任何时刻只管 SHARD_SIZE 个后端，内存低、不 OOM、连接稳。
#
# 账本 _done.jsonl 跨片统一累积（同 out_dir+batch-name），--resume 断点续跑（含容器重启）；
# namemap 跨片合并；全部片跑完再用全量 targets 生成一次完整 batch_summary。
set -eu

: "${BATCH:?必须设置 BATCH（批次名）}"
GATEWAY_URL="${GATEWAY_URL:-http://gateway:3000}"
GW_USER="${GATEWAY_USER:-admin}"
GW_PASS="${GATEWAY_PASSWORD:-admin123}"
SHARD_SIZE="${SHARD_SIZE:-50}"

mkdir -p /work/runs

# —— 结果属主跟随宿主用户（root 降权；见上一版说明）——
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

# —— 切片（只切有效行：去空行/注释，保证每片都是 SHARD_SIZE 个真目标）——
SHARD_DIR=/work/shards
rm -rf "$SHARD_DIR"; mkdir -p "$SHARD_DIR"
grep -vE '^[[:space:]]*($|#)' /work/batch.jsonl > "$SHARD_DIR/all.jsonl" || true
total=$(wc -l < "$SHARD_DIR/all.jsonl" | tr -d ' ')
split -l "$SHARD_SIZE" -d -a 4 "$SHARD_DIR/all.jsonl" "$SHARD_DIR/shard_"
nshard=$(ls "$SHARD_DIR"/shard_* 2>/dev/null | wc -l | tr -d ' ')
echo "[cell:$BATCH] 共 $total 个目标，按每片 $SHARD_SIZE 个切成 $nshard 片。"
: > "$SHARD_DIR/targets_all.txt"

i=0
for sh in "$SHARD_DIR"/shard_*; do
  i=$((i+1))
  cnt=$(wc -l < "$sh" | tr -d ' ')
  echo "[cell:$BATCH] ===== 片 $i/$nshard（$cnt 个）provision（清空网关、只装本片）====="
  rm -f /work/targets.txt
  if ! python3 /app/provision.py \
        --batch "$sh" --gateway "$GATEWAY_URL" --user "$GW_USER" --password "$GW_PASS" \
        --targets-out /work/targets.txt --map-out "$SHARD_DIR/map_$i.json" \
        --bearer-out /work/bearer.txt --force; then
    echo "[cell:$BATCH] 片 $i provision 失败，跳过本片。"
    continue
  fi
  # 合并 namemap（跨片累积，供 collect 回溯身份）
  python3 - "$SHARD_DIR/map_$i.json" <<'PY' || true
import json, os, sys
p = "/work/runs/namemap.json"
a = json.load(open(p)) if os.path.exists(p) else {}
try:
    a.update(json.load(open(sys.argv[1])))
except Exception:
    pass
json.dump(a, open(p, "w"), ensure_ascii=False, indent=2)
PY
  [ -s /work/targets.txt ] || { echo "[cell:$BATCH] 片 $i 无 targets，跳过。"; continue; }
  cat /work/targets.txt >> "$SHARD_DIR/targets_all.txt"
  BEARER="$(cat /work/bearer.txt 2>/dev/null || true)"
  set -- scan --batch /work/targets.txt --batch-name "$BATCH" \
     --gateway "$GATEWAY_URL" --gateway-user "$GW_USER" --gateway-password "$GW_PASS" \
     --gateway-reset before --resume --yes -o /work/runs
  [ -n "$BEARER" ] && set -- "$@" --header "Authorization: Bearer $BEARER"
  [ -n "${TOOL_TIMEOUT:-}" ] && set -- "$@" --tool-timeout "$TOOL_TIMEOUT"
  echo "[cell:$BATCH] ===== 片 $i/$nshard 扫描 $cnt 个 ====="
  python3 -m mcpfuzz.cli.main "$@" || echo "[cell:$BATCH] 片 $i scan 返回非 0，继续下一片。"
done

# —— 全部片跑完：用全量 targets 跑一次 --resume（已完成全跳过、不连网关），生成完整 batch_summary ——
if [ -s "$SHARD_DIR/targets_all.txt" ]; then
  echo "[cell:$BATCH] ===== 汇总：生成全量 batch_summary ====="
  python3 -m mcpfuzz.cli.main scan --batch "$SHARD_DIR/targets_all.txt" --batch-name "$BATCH" \
     --gateway "$GATEWAY_URL" --gateway-user "$GW_USER" --gateway-password "$GW_PASS" \
     --resume --yes -o /work/runs || echo "[cell:$BATCH] 汇总步骤返回非 0（账本已完整，可忽略）。"
fi
echo "[cell:$BATCH] 全部 $nshard 片完成。"
