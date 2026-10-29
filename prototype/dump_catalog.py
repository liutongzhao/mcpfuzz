"""第一步入口：连接一个 MCP 目标，打印并保存规范化工具清单。

用法：
  python dump_catalog.py <URL>                 # 直连无鉴权目标
  python dump_catalog.py <config.json> [名称]   # 读标准 mcpServers 配置（可带 headers 鉴权）

config.json 为标准格式：
  {"mcpServers": {"名称": {"url": "...", "headers": {"Authorization": "Bearer ..."}}}}
结果保存到 out/<server>_catalog.json。
"""
import json
import re
import sys
from pathlib import Path

from mcpfuzz.driver import fetch_catalog_sync

OUT = Path(__file__).resolve().parent / "out"


def first_line(text, n):
    lines = (text or "").splitlines()
    return (lines[0] if lines else "")[:n]


def resolve_target(arg: str, name: str | None):
    """返回 (url, headers)。arg 为 .json 文件则按 mcpServers 配置解析，否则当作 URL。"""
    if arg.endswith(".json") and Path(arg).exists():
        cfg = json.loads(Path(arg).read_text())
        servers = cfg.get("mcpServers", cfg)
        key = name or next(iter(servers))
        entry = servers[key]
        return entry["url"], entry.get("headers")
    return arg, None


def main():
    if len(sys.argv) < 2:
        sys.exit("用法: python dump_catalog.py <URL | config.json> [名称]")
    url, headers = resolve_target(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
    print(f"连接 {url} …" + ("（带鉴权头）" if headers else ""))
    target = fetch_catalog_sync(url, headers)
    print(f"服务器：{target.server_name} {target.server_version}  协议：{target.protocol_version}")
    print(f"工具数：{len(target.tools)}\n")

    for t in target.tools:
        print(f"● {t.name}  —— {first_line(t.description, 70)}")
        if not t.params:
            print("    （无参数）")
        for p in t.params:
            flags = []
            if p.required:
                flags.append("必填")
            if p.enum:
                flags.append(f"enum={p.enum[:4]}")
            if p.default is not None:
                flags.append(f"default={p.default!r}")
            ty = p.type + (f"<{p.item_type}>" if p.type == "array" else "")
            print(f"    - {p.path:22s} {ty:12s} {' '.join(flags):10s} {first_line(p.description, 50)}")

    OUT.mkdir(exist_ok=True)
    safe = re.sub(r"[^\w.-]", "_", (target.server_name or "server"))
    path = OUT / f"{safe}_catalog.json"
    path.write_text(json.dumps(target.to_dict(), ensure_ascii=False, indent=2))
    print(f"\n已保存：{path}")


if __name__ == "__main__":
    main()
