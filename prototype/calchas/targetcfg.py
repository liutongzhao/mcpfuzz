"""目标解析：参数可为直连 URL，或标准 mcpServers 配置文件（可带 headers）。"""
import json
from pathlib import Path


def resolve_target(arg: str, name: str | None = None):
    """返回 (url, headers)。arg 为 .json 文件则按 mcpServers 解析，否则当作 URL。"""
    if arg.endswith(".json") and Path(arg).exists():
        cfg = json.loads(Path(arg).read_text())
        servers = cfg.get("mcpServers", cfg)
        key = name or next(iter(servers))
        entry = servers[key]
        return entry["url"], entry.get("headers")
    return arg, None
