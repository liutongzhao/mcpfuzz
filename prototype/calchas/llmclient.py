"""Generic LLM relay client: one system+user completion. Reused by the planner and value-extraction fallback.

Uses curl (python urllib's SSL fails in some environments); does not pass temperature (this relay would 502).
"""
from __future__ import annotations

import json
import subprocess


def complete(system: str, user: str, max_tokens: int = 2000, timeout: int = 120) -> str:
    """One system+user completion. Goes through multi-model failover (see llm_failover): on failure the current
    model is swapped for a backup; if all fail it raises AllModelsUnavailable (caught by the batch layer to pause)."""
    from calchas import llm_failover
    return llm_failover.complete(system, user, max_tokens=max_tokens, timeout=timeout)
