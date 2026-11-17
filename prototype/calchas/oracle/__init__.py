"""判定器（Oracle）：造诱饵 + 盯信号 + 下结论。第一期含 OOB 回连与响应回显两个通道。"""
from .core import Oracle
from .probe import Hit, Probe, ProbeRegistry, mint_token
from .verdict import CONFIRMED, NOT_TRIGGERED, Finding

__all__ = ["Oracle", "Probe", "Hit", "ProbeRegistry", "mint_token",
           "Finding", "CONFIRMED", "NOT_TRIGGERED"]
