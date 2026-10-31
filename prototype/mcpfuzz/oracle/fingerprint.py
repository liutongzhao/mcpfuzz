"""错误指纹：从响应/报错正文里识别"注入抵达了解释器"的弱证据（Tier-3）。

单独出现只作"疑似有"旁证，不进"确认"。各类别一组通用正则，不针对任何服务器。
"""
from __future__ import annotations

import re

from mcpfuzz.sink.types import AI, CI, PT, SSRF

_PATTERNS = {
    CI: [
        r"/bin/(?:sh|bash)\b",
        r"\b(?:command not found|not found)\b",
        r"\bsyntax error\b",
        r"\bunexpected (?:token|EOF|end of)\b",
        r"\bsh:\s",
    ],
    AI: [
        r"\bunknown option\b",
        r"\bunrecognized option\b",
        r"\binvalid option\b",
        r"\bunknown (?:flag|argument|switch)\b",
        r"\bunexpected argument\b",
        r"^usage:",
    ],
    PT: [
        r"\bENOENT\b",
        r"\bNo such file or directory\b.*/(?:etc|root|home|var|usr)/",
        r"\b(?:EACCES|permission denied)\b.*/(?:etc|root)/",
    ],
    SSRF: [
        r"\b(?:ECONNREFUSED|connection refused)\b",
        r"\b(?:ETIMEDOUT|connection timed out)\b",
        r"\bno route to host\b",
    ],
}

_COMPILED = {k: [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in v] for k, v in _PATTERNS.items()}


def error_fingerprint(text: str, vuln_class: str) -> str | None:
    """命中则返回匹配到的片段（最多 120 字），否则 None。"""
    if not text:
        return None
    for rx in _COMPILED.get(vuln_class, []):
        m = rx.search(text)
        if m:
            i = m.start()
            return text[max(0, i - 20): i + 100]
    return None
