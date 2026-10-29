"""响应回显通道：在工具返回文本里匹配约定的标记。

- embed(token)：给出载荷里要回显出来的 marker（默认就是 token）。
- observe(probe, 返回文本)：命中则返回 Hit（含匹配到的片段）。
对路径穿越读也适用——此时 probe.expect 放越界文件的特征串。
"""
from __future__ import annotations

import time

from .probe import Hit, Probe


class ReflectionChannel:
    def embed(self, token: str) -> str:
        return token

    def observe(self, probe: Probe, response_text: str) -> Hit | None:
        if not response_text:
            return None
        for marker in (probe.expect or [probe.token]):
            if marker and marker in response_text:
                i = response_text.find(marker)
                snippet = response_text[max(0, i - 40): i + len(marker) + 40]
                return Hit(probe.token, "reflection", time.strftime("%Y-%m-%dT%H:%M:%S"),
                           {"marker": marker, "snippet": snippet})
        return None
