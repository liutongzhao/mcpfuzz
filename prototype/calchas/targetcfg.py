"""Target resolution: the argument may be a direct URL, or a standard mcpServers config file (optionally with headers)."""
import json
from pathlib import Path


def resolve_target(arg: str, name: str | None = None):
    """Return (url, headers). If arg is a .json file, parse it as mcpServers; otherwise treat it as a URL."""
    if arg.endswith(".json") and Path(arg).exists():
        cfg = json.loads(Path(arg).read_text())
        servers = cfg.get("mcpServers", cfg)
        key = name or next(iter(servers))
        entry = servers[key]
        return entry["url"], entry.get("headers")
    return arg, None
