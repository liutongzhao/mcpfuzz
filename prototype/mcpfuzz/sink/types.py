"""Sink 推断的数据结构与封闭集 + 类别权重（地板 + 抬升）。

设计要点（见 docs/Sink推断模块设计.md）：
- 在"注入类别 / 危险边界"这一封闭集合层枚举，不在"后端程序"层。
- 产出是**软先验**（每个启用类别一个权重），不是单一硬标签；下游只排序、不闸门。
- "地板 + 抬升"：任何非惰性参数的每个启用类别都先给一个非零地板（fail-open，
  保证召回有下界、不随分类误差归零）；规则 / 大模型只把相关类别从地板往上抬，取 max 合并。
"""
from __future__ import annotations

from dataclasses import dataclass, field

# 注入类别封闭集（按"危险边界"抽象，不含任何具体程序名）
CI = "command_injection"
AI = "argument_injection"
PT = "path_traversal"
SSRF = "ssrf"
QI = "query_injection"
CODE = "code_injection"
NONE = "none"
SINK_TYPES = {CI, AI, PT, SSRF, QI, CODE, NONE}

# 本阶段启用的类别（阶段范围配置，≠ 对单参数的闸门；QI/CODE 留第二阶段）。
PHASE1_CLASSES = (CI, AI, PT, SSRF)

# 权重档位。地板保证非零（任一启用类别都会被下游分到最小载荷预算）；抬升只增不减，合并取 max。
FLOOR = 0.1      # 地板：任何非惰性参数的每个启用类别都 ≥ 此值
W_LOW = 0.4      # 弱证据（描述命中 / 大模型 low）
W_MED = 0.7      # 中证据（参数名命中 / 大模型 medium）
W_HIGH = 1.0     # 强证据（大模型 high）

CONF_WEIGHT = {"low": W_LOW, "medium": W_MED, "high": W_HIGH}


@dataclass
class Raise:
    """一条"抬升"证据：把某个类别抬到某权重。来自规则或大模型。"""
    cls: str
    weight: float
    source: str      # rule | llm
    reason: str = ""


@dataclass
class ParamSinkPrior:
    """一个参数的注入类别软先验。

    class_weights 只覆盖"启用的类别"，且仅对**非惰性**参数非空；每个值 ≥ FLOOR。
    provenance 记录每个被抬到地板以上的类别的证据，供调试与报告。
    """
    tool: str
    param_path: str
    param_type: str
    class_weights: dict = field(default_factory=dict)   # {class: weight>=FLOOR}
    inert: bool = False
    inert_reason: str = ""
    provenance: dict = field(default_factory=dict)      # {class: [证据串, ...]}

    def ranked_classes(self) -> list[str]:
        """按权重从高到低返回启用类别（供下游排序分预算）。"""
        return [c for c, _ in sorted(self.class_weights.items(), key=lambda kv: -kv[1])]

    def weight_of(self, cls: str) -> float:
        return self.class_weights.get(cls, 0.0)
