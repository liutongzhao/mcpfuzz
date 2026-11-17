#!/usr/bin/env bash
# 网关首次启动后执行一次（可重复执行）：把 mcphub 调成检测所需的设置。
#   - routing.enableBearerAuth=false   MCP 端点 /mcp/<server> 免鉴权（端口只绑 127.0.0.1，不对外）
#   - toolResultCompression=false      工具输出压缩会截断回显，导致漏报
#   - smartRouting=false               智能路由会裁剪 tools/list
# 管理界面登录（skipAuth）保持开启。
# 用法：./configure.sh [网关地址，默认 http://127.0.0.1:3000]   （读同目录 .env 的 GATEWAY_PASSWORD）
set -euo pipefail
cd "$(dirname "$0")"
BASE="${1:-http://127.0.0.1:${GATEWAY_PORT:-3000}}"
PASS="$(grep -E '^GATEWAY_PASSWORD=' .env | cut -d= -f2-)"

TOKEN=""
for _ in $(seq 1 30); do   # 刚启动时管理 API 可能还没就绪
  TOKEN="$(curl -s -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"$PASS\"}" \
    | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))' 2>/dev/null || true)"
  [ -n "$TOKEN" ] && break
  sleep 3
done
[ -n "$TOKEN" ] || { echo "login failed: check GATEWAY_PASSWORD in .env" >&2; exit 1; }

curl -s -X PUT "$BASE/api/system-config" -H "x-auth-token: $TOKEN" -H 'Content-Type: application/json' \
  -d '{"routing":{"enableBearerAuth":false},"toolResultCompression":{"enabled":false},"smartRouting":{"enabled":false}}' \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print("system-config:", "ok" if d.get("success") else d)'

CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/mcp" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"configure","version":"1"}}}')"
echo "MCP endpoint without auth: HTTP $CODE (expect 200)"
[ "$CODE" = "200" ]
