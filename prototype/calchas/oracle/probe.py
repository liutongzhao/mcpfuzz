"""探针与命中证据的基础数据结构，以及 token 铸造与登记表。"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field


def mint_token() -> str:
    """生成唯一、不可能自然出现、URL/shell 安全、可在文本中匹配的 token。"""
    return "mcpf" + secrets.token_hex(5)


@dataclass
class Probe:
    token: str
    channel: str                       # "oob" | "reflection"
    embed: str                         # 交给载荷层嵌入的可观测物（回连URL / 回显marker）
    meta: dict = field(default_factory=dict)   # tool/param/payload 等溯源信息
    expect: list = field(default_factory=list) # 回显通道要在返回里匹配的字符串（默认 [token]）
    created_at: float = field(default_factory=time.time)


@dataclass
class Hit:
    token: str
    channel: str
    time: str | None = None
    evidence: dict = field(default_factory=dict)


class ProbeRegistry:
    """token → Probe 的登记表，用于溯源与留证。"""

    def __init__(self):
        self._probes: dict[str, Probe] = {}

    def add(self, probe: Probe):
        self._probes[probe.token] = probe

    def get(self, token: str) -> Probe | None:
        return self._probes.get(token)

    def all(self) -> list[Probe]:
        return list(self._probes.values())
