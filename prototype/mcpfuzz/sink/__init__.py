"""Sink 推断：规则兜底 + 大模型主判，输出每个参数的候选 sink（高/低 + source）。"""
from .core import SinkInferencer
from .types import SINK_TYPES, ParamSink, SinkLabel

__all__ = ["SinkInferencer", "ParamSink", "SinkLabel", "SINK_TYPES"]
