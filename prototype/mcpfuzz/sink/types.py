"""Sink 推断的数据结构与封闭集。"""
from __future__ import annotations

from dataclasses import dataclass, field

# sink 封闭集（按"危险操作种类"抽象，不含任何具体程序名）
CI = "command_injection"
AI = "argument_injection"
PT = "path_traversal"
SSRF = "ssrf"
QI = "query_injection"
CODE = "code_injection"
NONE = "none"
SINK_TYPES = {CI, AI, PT, SSRF, QI, CODE, NONE}


@dataclass
class SinkLabel:
    type: str
    confidence: str          # high | low
    source: str              # rule | llm | both
    reason: str = ""


@dataclass
class ParamSink:
    tool: str
    param_path: str
    param_type: str
    sinks: list = field(default_factory=list)   # list[SinkLabel]
