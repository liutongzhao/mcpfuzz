"""第一步入口：连接一个 MCP 目标，打印并保存规范化工具清单。

用法：python dump_catalog.py [URL]
默认连 git 靶机。结果保存到 out/<server>_catalog.json。
"""
import json
import re
import sys
from pathlib import Path

from mcpfuzz.driver import fetch_catalog_sync

DEFAULT_URL = "http://43.133.80.249:20001/mcp"
OUT = Path(__file__).resolve().parent / "out"


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    print(f"连接 {url} …")
    target = fetch_catalog_sync(url)
    print(f"服务器：{target.server_name} {target.server_version}  协议：{target.protocol_version}")
    print(f"工具数：{len(target.tools)}\n")

    for t in target.tools:
        print(f"● {t.name}  —— {(t.description or '').splitlines()[0][:70]}")
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
            desc = (p.description or "").splitlines()[0][:50]
            print(f"    - {p.path:22s} {ty:12s} {' '.join(flags):10s} {desc}")

    OUT.mkdir(exist_ok=True)
    safe = re.sub(r"[^\w.-]", "_", (target.server_name or "server"))
    path = OUT / f"{safe}_catalog.json"
    path.write_text(json.dumps(target.to_dict(), ensure_ascii=False, indent=2))
    print(f"\n已保存：{path}")


if __name__ == "__main__":
    main()
