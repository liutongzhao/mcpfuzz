"""Step-one entry: connect to an MCP target, print and save the normalized tool catalog.

Usage:
  python dump_catalog.py <URL>                 # direct connect, no auth
  python dump_catalog.py <config.json> [name]   # read a standard mcpServers config (optionally with header auth)

config.json is the standard format:
  {"mcpServers": {"name": {"url": "...", "headers": {"Authorization": "Bearer ..."}}}}
Results are saved to out/<server>_catalog.json.
"""
import json
import re
import sys
from pathlib import Path

from calchas.driver import fetch_catalog_sync

OUT = Path(__file__).resolve().parent / "out"


def first_line(text, n):
    lines = (text or "").splitlines()
    return (lines[0] if lines else "")[:n]


def resolve_target(arg: str, name: str | None):
    """Return (url, headers). If arg is a .json file, parse it as an mcpServers config; otherwise treat it as a URL."""
    if arg.endswith(".json") and Path(arg).exists():
        cfg = json.loads(Path(arg).read_text())
        servers = cfg.get("mcpServers", cfg)
        key = name or next(iter(servers))
        entry = servers[key]
        return entry["url"], entry.get("headers")
    return arg, None


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: python dump_catalog.py <URL | config.json> [name]")
    url, headers = resolve_target(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
    print(f"connecting {url} ..." + (" (with auth header)" if headers else ""))
    target = fetch_catalog_sync(url, headers)
    print(f"server: {target.server_name} {target.server_version}  protocol: {target.protocol_version}")
    print(f"tools: {len(target.tools)}\n")

    for t in target.tools:
        print(f"● {t.name}  —— {first_line(t.description, 70)}")
        if not t.params:
            print("    (no parameters)")
        for p in t.params:
            flags = []
            if p.required:
                flags.append("required")
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
    print(f"\nsaved: {path}")


if __name__ == "__main__":
    main()
