"""通用大模型中转客户端：一次 system+user 的补全。供规划器、取值兜底复用。

用 curl（部分环境 python urllib 的 SSL 会失败）；不传 temperature（该中转会 502）。
"""
from __future__ import annotations

import json
import subprocess

from mcpfuzz.llm_config import API_KEY, BASE_URL, MODEL


def complete(system: str, user: str, max_tokens: int = 2000, timeout: int = 120) -> str:
    """一次 system+user 补全。走多模型故障切换（见 llm_failover）：当前模型失败自动切备用，
    全部失败抛 AllModelsUnavailable（由批量层捕获暂停）。"""
    from mcpfuzz import llm_failover
    return llm_failover.complete(system, user, max_tokens=max_tokens, timeout=timeout)
