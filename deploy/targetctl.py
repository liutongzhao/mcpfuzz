#!/usr/bin/env python3
"""靶机管理工具：按约定统一构建/启动/停止/重置 MCP 靶机容器。只用标准库。

约定：
  - 每个靶机 = targets/<id>/meta.json；可选 targets/<id>/Dockerfile 覆盖模板。
  - 容器对外统一在内部 8000 端口提供 Streamable HTTP；对外公网端口取 meta.port。
  - 所有容器 + OOB 采集服务接入同一 docker 网络，容器内用 http://<oob名>:9100/<token> 回连。
  - 全局配置见 manifest.json。

用法：
  python3 targetctl.py list
  python3 targetctl.py infra-up            # 建网络 + 构建并启动 OOB 采集服务
  python3 targetctl.py build  <id>
  python3 targetctl.py start  <id>
  python3 targetctl.py stop   <id>
  python3 targetctl.py reset  <id>         # 删容器重新 start（回到干净状态）
  python3 targetctl.py rm     <id>
  python3 targetctl.py infra-down
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CFG = json.loads((ROOT / "manifest.json").read_text())
NET = CFG["network"]
MEM = CFG.get("mem_limit", "1g")
OOB = CFG["oob"]


def run(cmd, check=True, capture=False):
    print("  $", " ".join(cmd), flush=True)
    r = subprocess.run(cmd, text=True, capture_output=capture)
    if check and r.returncode != 0:
        if capture:
            sys.stderr.write(r.stderr)
        sys.exit(f"命令失败（退出码 {r.returncode}）")
    return r


def load(tid):
    meta = ROOT / "targets" / tid / "meta.json"
    if not meta.exists():
        sys.exit(f"找不到靶机：{tid}（缺 {meta}）")
    return json.loads(meta.read_text())


def all_targets():
    return sorted(p.parent.name for p in (ROOT / "targets").glob("*/meta.json"))


def image_tag(tid):
    return f"mcp/{tid}"


def container_name(tid):
    return f"mcp-{tid}"


def ensure_network():
    r = run(["docker", "network", "ls", "--format", "{{.Name}}"], capture=True)
    if NET not in r.stdout.split():
        run(["docker", "network", "create", NET])


def cmd_list(_):
    r = run(["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Status}}\t{{.Ports}}"], capture=True)
    status = {}
    for line in r.stdout.splitlines():
        parts = line.split("\t")
        if parts:
            status[parts[0]] = parts[1:] if len(parts) > 1 else []
    print(f"{'ID':40s} {'端口':7s} {'类型':18s} {'CVE':16s} 状态")
    for tid in all_targets():
        m = load(tid)
        st = status.get(container_name(tid))
        state = st[0] if st else "未创建"
        print(f"{tid:40s} {str(m.get('port','')):7s} {m.get('vuln_class',''):18s} {m.get('cve',''):16s} {state}")


def cmd_infra_up(_):
    ensure_network()
    run(["docker", "build", "-t", OOB["image"], str(ROOT / "infra" / "oob")])
    run(["docker", "rm", "-f", OOB["name"]], check=False)
    run(["docker", "run", "-d", "--name", OOB["name"], "--network", NET,
         "-p", f"{OOB['host_port']}:9100", "--restart", "unless-stopped", OOB["image"]])
    print(f"OOB 采集服务已启动：容器内 http://{OOB['name']}:9100 ，主机 http://0.0.0.0:{OOB['host_port']}")


def cmd_infra_down(_):
    run(["docker", "rm", "-f", OOB["name"]], check=False)


def cmd_build(args):
    m = load(args.id)
    tdir = ROOT / "targets" / args.id
    own = tdir / "Dockerfile"
    if own.exists():
        run(["docker", "build", "-t", image_tag(args.id), str(tdir)])
    else:
        tpl = ROOT / "templates" / ("node.Dockerfile" if m["ecosystem"] == "npm" else "python.Dockerfile")
        run(["docker", "build", "-t", image_tag(args.id), "-f", str(tpl),
             "--build-arg", f"PKG={m['package']}", "--build-arg", f"VER={m['vuln_version']}",
             str(ROOT / "templates")])


def cmd_start(args):
    m = load(args.id)
    ensure_network()
    cmd = ["docker", "run", "-d", "--name", container_name(args.id), "--network", NET,
           "-p", f"{m['port']}:8000", "--memory", MEM]
    for k, v in (m.get("env") or {}).items():
        cmd += ["-e", f"{k}={v}"]
    cmd += ["-e", f"START_CMD={m['start_cmd']}", image_tag(args.id)]
    run(cmd)
    print(f"已启动 {args.id} ：http://43.133.80.249:{m['port']}/mcp （OOB: http://{OOB['name']}:9100）")


def cmd_stop(args):
    run(["docker", "stop", container_name(args.id)], check=False)


def cmd_rm(args):
    run(["docker", "rm", "-f", container_name(args.id)], check=False)


def cmd_reset(args):
    cmd_rm(args)
    cmd_start(args)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("list", "infra-up", "infra-down"):
        sub.add_parser(name)
    for name in ("build", "start", "stop", "reset", "rm"):
        p = sub.add_parser(name)
        p.add_argument("id")
    args = ap.parse_args()
    {"list": cmd_list, "infra-up": cmd_infra_up, "infra-down": cmd_infra_down,
     "build": cmd_build, "start": cmd_start, "stop": cmd_stop,
     "reset": cmd_reset, "rm": cmd_rm}[args.cmd](args)


if __name__ == "__main__":
    main()
