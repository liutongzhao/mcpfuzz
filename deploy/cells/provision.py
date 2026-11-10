#!/usr/bin/env python3
"""把一批「全网搜集的 MCP」清单灌进本 cell 的 mcphub 网关，产出扫描用的 targets.txt。

输入：verified_call_ok.jsonl 的行子集（见 batches/sample.jsonl）。每行一个 JSON，
至少含 name / launch；registryType / identifier / tool_names / tools_count 可选（用于结果回溯）。

流程：
  1. 轮询登录网关（兼作就绪探测，等 mcphub 冷启动起来）。
  2. 首次运行时清空网关已有后端，保证本 cell 只含这一批（restart 续跑时不重清）。
  3. 每条 name 消毒成网关合法后端名；launch[0]=command、launch[1:]=args，拼成 stdio 配置。
  4. POST /api/servers/batch 分块批量添加（某块失败则逐条重试，部分失败不中断）。
  5. 写 targets.txt（每行 /mcp/{后端名}，给 mcpfuzz --batch 用）、namemap.json（后端名→原始身份+期望工具）。
  6. 尽力铸一把 bearer key 写到 bearer.txt（给 MCP 端点鉴权用）；铸不出则回退登录 JWT。

幂等：targets.txt 已存在且非空时跳过灌清单（容器 restart 续跑时不重复灌）。纯标准库。

说明：管理 API 用 `x-auth-token` 头鉴权；MCP 端点用 `Authorization: Bearer`（二者不同，见记忆 mcphub-gateway）。
"""
import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def _req(base, method, path, body=None, token=None, timeout=15):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base.rstrip("/") + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("x-auth-token", token)   # mcphub 管理 API 用 x-auth-token，不是 Bearer
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        raise RuntimeError(f"HTTP {e.code} {method} {path}: {raw[:200]}")
    return json.loads(raw) if raw.strip() else {}


def login(base, user, password, tries=60, interval=5):
    """轮询登录；兼作网关就绪探测（mcphub 首启要几秒）。拿不到 token 就退出。"""
    last = ""
    for i in range(tries):
        try:
            d = _req(base, "POST", "/api/auth/login",
                     {"username": user, "password": password}, timeout=10)
            tok = d.get("token") or (d.get("data") or {}).get("token")
            if tok:
                print(f"  网关已就绪，登录成功。", flush=True)
                return tok
            last = str(d)[:160]
        except Exception as e:
            last = str(e)[:160]
        print(f"  等待网关就绪/登录…({i + 1}/{tries}) {last}", flush=True)
        time.sleep(interval)
    sys.exit(f"登录网关失败（{tries} 次仍不可用）：{last}")


def mint_bearer(base, token):
    """铸一把长期 bearer key 给 MCP 端点用（/mcp/{server} 要 `Authorization: Bearer mcphub_...`）。

    mcphub 铸 key 必须带 `accessType`（缺了会 400 Invalid accessType → 回退 JWT → MCP 端点 401）；
    实测有效值是 `all`（全量访问，allowedServers=[] 即所有后端）。返回的 key 在 data.token（mcphub_ 前缀）。
    为兼容不同版本，accessType 候选从 all 起逐个试；字段名也多解析几种。失败返回 None。"""
    bodies = [{"name": "cell-scan", "accessType": at} for at in ("all", "full", "readWrite", "read")]
    for path in ("/api/auth/keys", "/api/keys"):
        for body in bodies:
            try:
                d = _req(base, "POST", path, body, token=token)
                d = d.get("data", d)
                if isinstance(d, dict):
                    for k in ("token", "key", "value", "apiKey", "secret"):
                        if d.get(k):
                            return d[k]
            except Exception:
                continue
    return None


def list_servers(base, token):
    try:
        d = _req(base, "GET", "/api/servers", token=token)
        data = d.get("data", d)
        if isinstance(data, dict):
            return [k for k in data.keys() if k not in ("success", "message")]
        if isinstance(data, list):
            return [s.get("name") for s in data if isinstance(s, dict) and s.get("name")]
    except Exception as e:
        print(f"  列后端失败（忽略）：{str(e)[:120]}", flush=True)
    return []


def reset_servers(base, token):
    names = list_servers(base, token)
    for n in names:
        try:
            _req(base, "DELETE", f"/api/servers/{n}", token=token)
        except Exception as e:
            print(f"  删后端 {n} 失败（忽略）：{str(e)[:120]}", flush=True)
    if names:
        print(f"  已清空网关原有 {len(names)} 个后端。", flush=True)


def sanitize(name, used):
    """网关后端名只允许字母数字点下划线连字符；其余换成 _，并处理重名。"""
    gw = re.sub(r"[^A-Za-z0-9._-]", "_", name or "server").strip("._-") or "server"
    base, i = gw, 2
    while gw in used:
        gw = f"{base}_{i}"
        i += 1
    used.add(gw)
    return gw


def main():
    ap = argparse.ArgumentParser(description="把 MCP 清单灌进 mcphub 网关并产出 targets.txt")
    ap.add_argument("--batch", required=True, help="批次 jsonl（verified_call_ok 的行子集）")
    ap.add_argument("--gateway", required=True, help="网关基址，如 http://gateway:3000")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="admin123")
    ap.add_argument("--targets-out", required=True, help="输出 targets.txt（给 mcpfuzz --batch）")
    ap.add_argument("--map-out", required=True, help="输出 namemap.json（后端名→原始身份）")
    ap.add_argument("--bearer-out", default=None, help="输出 bearer.txt（给 MCP 端点鉴权）")
    ap.add_argument("--no-reset", action="store_true", help="不清空网关已有后端")
    ap.add_argument("--force", action="store_true", help="即使 targets.txt 已存在也重灌")
    ap.add_argument("--chunk", type=int, default=10, help="批量添加每块条数（调小以控 add 后 autoConnect 的瞬时子进程峰值）")
    args = ap.parse_args()

    tout, mout = Path(args.targets_out), Path(args.map_out)
    tout.parent.mkdir(parents=True, exist_ok=True)
    mout.parent.mkdir(parents=True, exist_ok=True)

    if tout.exists() and tout.read_text(encoding="utf-8").strip() and not args.force:
        print(f"[provision] {tout} 已存在 → 跳过灌清单（容器 restart 续跑）。", flush=True)
        return

    # 读清单
    entries = []
    for ln in Path(args.batch).read_text(encoding="utf-8").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        try:
            d = json.loads(ln)
        except json.JSONDecodeError:
            print(f"  跳过非法 JSON 行：{ln[:80]}", flush=True)
            continue
        if not d.get("name") or not (d.get("launch") or []):
            print(f"  跳过缺 name/launch 的条目：{str(d)[:80]}", flush=True)
            continue
        entries.append(d)
    print(f"[provision] 清单 {len(entries)} 条；登录网关 {args.gateway} …", flush=True)

    token = login(args.gateway, args.user, args.password)

    if args.bearer_out:
        bearer = mint_bearer(args.gateway, token)
        Path(args.bearer_out).write_text(bearer or token or "", encoding="utf-8")
        print(f"  bearer 写入 {args.bearer_out}（{'铸新 key' if bearer else '回退登录 JWT'}）。", flush=True)

    if not args.no_reset:
        reset_servers(args.gateway, token)

    # 清单 → 网关 stdio 配置
    used, servers, mapping = set(), [], {}
    for d in entries:
        launch = d["launch"]
        gw = sanitize(d["name"], used)
        # enabled=False：注册时【不自动连接】。mcphub 默认 enabled=true 会把所有注册后端全部
        # 自动拉起成常驻子进程（实测灌 50 个→70 子进程→吃满 3G→OOM 重启），使"检测时才上线"失效。
        # 设 false 后 mcphub 只登记不拉起，由 runner 扫到某目标时 enable 单独拉起、扫完 disable。
        servers.append({"name": gw, "enabled": False, "config": {
            "type": "stdio", "command": launch[0], "args": launch[1:], "env": {}}})
        mapping[gw] = {"name": d["name"], "identifier": d.get("identifier"),
                       "registryType": d.get("registryType"), "launch": launch,
                       "tools_expected": d.get("tool_names"),
                       "tools_count_expected": d.get("tools_count")}

    # 分块批量添加；某块失败则逐条重试
    added = 0
    for i in range(0, len(servers), args.chunk):
        chunk = servers[i:i + args.chunk]
        try:
            _req(args.gateway, "POST", "/api/servers/batch", {"servers": chunk}, token=token, timeout=60)
            added += len(chunk)
        except Exception as e:
            print(f"  批量第 {i // args.chunk + 1} 块失败，改逐条：{str(e)[:120]}", flush=True)
            for s in chunk:
                try:
                    _req(args.gateway, "POST", "/api/servers", s, token=token, timeout=30)
                    added += 1
                except Exception as e2:
                    print(f"    添加 {s['name']} 失败（忽略）：{str(e2)[:100]}", flush=True)
        # 关键：add 后立即禁用本块。mcphub 对注册的后端会 autoConnect 全部拉起成常驻 stdio 子进程
        # （实测忽略请求里的 enabled=false），一次灌几十个会让「尚未轮到检测的」后端一直连着、
        # 子进程累积到吃满内存 → 网关 OOM 反复重启 → runner 大面积连接失败。这里 add 完立刻 disable
        # （实测 disable 会杀子进程，趁 npx 冷启动未完成前标记 disabled 可把峰值压到很低），
        # 使所有后端回到「不连」状态；扫描时再由 runner 逐个 enable → 扫 → disable，网关任意时刻只连 1 个。
        for s in chunk:
            try:
                _req(args.gateway, "POST", f"/api/servers/{s['name']}/toggle",
                     {"enabled": False}, token=token, timeout=15)
            except Exception:
                pass

    tout.write_text("\n".join(f"{args.gateway.rstrip('/')}/mcp/{s['name']}" for s in servers) + "\n",
                    encoding="utf-8")
    mout.write_text(json.dumps(mapping, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[provision] 完成：尝试 {len(servers)} 个，确认约 {added} 个；"
          f"targets→{tout}  map→{mout}", flush=True)


if __name__ == "__main__":
    main()
