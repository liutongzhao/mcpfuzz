"""编排器数据结构：调用计划、执行结果。"""
from __future__ import annotations

from dataclasses import dataclass, field

# 五态判定（见 docs/判定方法论.md）
CONFIRMED = "confirmed"        # 出现铁证，或可证经复测 → 确认漏洞
SUSPECTED = "suspected"        # 仅弱证据（错误指纹 / SSRF 回连未越边界）→ 疑似有，待人工复核
LIKELY_CLEAN = "likely_clean"  # 确有证据表明已触达 sink，但全套无命中 → 疑似无漏洞
UNREACHED = "unreached"        # 载荷确实发出了，但全部被目标工具拒绝/报错且基线不可达 → 可能没触达 sink
SKIPPED = "skipped"            # 工具侧原因根本没发出有效测试：计划不可达 / 前置步骤报错 / 会话异常 /
                               # 目标实参取值失败。这不等于"无漏洞"，统计时必须与 UNREACHED 分开。

# 可用性/拒绝服务观测的 sink 标识。崩溃不是针对某个参数的判定，而是"整套打完后服务器被打到
# 无响应"的整工具级发现（见 docs/漏洞类型与检测手段.md 第6类）。用独立 sink 值承载，便于在
# 统计与报告里把它从 per-param 五态里单独拎出，不污染参数覆盖率。
DOS = "denial_of_service"


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
