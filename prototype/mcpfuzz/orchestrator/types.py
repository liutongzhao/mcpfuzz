"""编排器数据结构：调用计划、执行结果。"""
from __future__ import annotations

from dataclasses import dataclass, field

# 四态判定
CONFIRMED = "confirmed"        # 判定器命中 → 确认漏洞
LIKELY_CLEAN = "likely_clean"  # 调用正常返回但无信号 → 大概率到了 sink 无漏洞
UNREACHED = "unreached"        # 载荷确实发出了，但全部被目标工具拒绝/报错 → 大概率没触达 sink（已尝试）
SKIPPED = "skipped"            # 工具侧原因根本没发出有效测试：计划不可达 / 前置步骤报错 / 会话异常 /
                               # 目标实参取值失败。这不等于"无漏洞"，统计时必须与 UNREACHED 分开。


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
