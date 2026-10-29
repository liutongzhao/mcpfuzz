"""编排器数据结构：调用计划、执行结果。"""
from __future__ import annotations

from dataclasses import dataclass, field

# 三态判定
CONFIRMED = "confirmed"        # 判定器命中 → 确认漏洞
LIKELY_CLEAN = "likely_clean"  # 调用正常返回但无信号 → 大概率到了 sink 无漏洞
UNREACHED = "unreached"        # 没打到 sink（目标参数被校验拒 / 前置没跑通）


@dataclass
class Step:
    step: int
    tool: str
    args: dict                 # {param: {"src":"literal","value":..} | {"src":"from_step","step":n,"extract":".."}}


@dataclass
class Plan:
    steps: list                # list[Step]，最后一步即目标工具
    reachable: bool = True
    note: str = ""


@dataclass
class Finding:
    tool: str
    param: str
    sink: str
    status: str                # CONFIRMED / LIKELY_CLEAN / UNREACHED
    payload: str = ""
    channel: str = ""
    evidence: dict = field(default_factory=dict)
    sequence: list = field(default_factory=list)   # 可复现序列（前置调用 + 命中载荷）
    note: str = ""
