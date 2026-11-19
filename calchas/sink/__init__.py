"""Sink inference: structural pre-filter + one deterministic multi-label classifier (LLM or keyword),
emitting the injection classes each parameter is tested for."""
from .core import SinkInferencer, is_inert
from .types import (CI, AI, PT, SSRF, QI, CODE, PHASE1_CLASSES, OPERATIONS, SINK_TYPES,
                    ParamSinkPrior, operations_to_classes)

__all__ = ["SinkInferencer", "is_inert", "ParamSinkPrior", "operations_to_classes", "SINK_TYPES",
           "PHASE1_CLASSES", "OPERATIONS", "CI", "AI", "PT", "SSRF", "QI", "CODE"]
