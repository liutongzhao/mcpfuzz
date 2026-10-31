"""载荷层数据结构：探针（ProbeSpec）—— 载荷合成与判定之间的接口对象。

见 docs/载荷合成模块设计.md。一条探针 = 活性载荷 + 良性对照 + 漏洞类 + 观测通道 + 命中判据 + 观测物。
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ProbeSpec:
    tool: str
    param_path: str
    vuln_class: str          # command_injection / argument_injection / path_traversal / ssrf ...
    value: str               # 活性载荷：最终塞进参数的字符串（可能已内嵌 oracle 诱饵）
    channel: str             # 观测通道：oob / inband / timing / differential
    control: str | None = None   # 良性对照值（timing/differential 必需；直接取证型可空，用基线兜底）
    probe: object = None     # oracle 铸造的观测物（oob/inband 需要；timing/differential 为 None）
    expect: list = field(default_factory=list)   # inband 要在响应里匹配的签名（默认 [token]）
    delay_target: float = 0.0   # timing：期望额外延时（秒）
    technique: str = ""      # 便于报告，如 'ci:;echo' / 'pt:../etc/passwd'
    rank: int = 0            # 越小越先发，支持早停
