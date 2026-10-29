"""通用大模型中转客户端：一次 system+user 的补全。供规划器、取值兜底复用。

用 curl（部分环境 python urllib 的 SSL 会失败）；不传 temperature（该中转会 502）。
"""
from __future__ import annotations

import json
import subprocess

from mcpfuzz.llm_config import API_KEY, BASE_URL, MODEL


def complete(system: str, user: str, max_tokens: int = 2000, timeout: int = 120) -> str:
    payload = json.dumps({
        "model": MODEL,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "max_tokens": max_tokens,
    })
    p = subprocess.run(
        ["curl", "-sS", "-m", str(timeout), BASE_URL,
         "-H", f"Authorization: Bearer {API_KEY}", "-H", "Content-Type: application/json",
         "-d", "@-", "-w", "\n%{http_code}"],
        input=payload, capture_output=True, text=True,
    )
    if p.returncode != 0:
        raise RuntimeError(f"curl 失败({p.returncode}): {p.stderr.strip()[:200]}")
    body, _, code = p.stdout.rpartition("\n")
    if code != "200":
        raise RuntimeError(f"HTTP {code}: {body[:200]}")
    return json.loads(body)["choices"][0]["message"]["content"]
