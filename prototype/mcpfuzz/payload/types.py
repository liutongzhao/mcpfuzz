"""载荷的数据结构。"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Payload:
    tool: str
    param_path: str
    value: str            # 最终要塞进参数的字符串
    sink: str             # command_injection / ssrf / path_traversal
    channel: str          # oob / reflection（决定判定器怎么验）
    probe: object         # 判定器铸造的 Probe（带唯一 token）
    technique: str        # 便于报告，如 'ci:; curl' / 'pt:../etc/passwd'
    rank: int = 0         # 越小越先发，支持编排器早停
