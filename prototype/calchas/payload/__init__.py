"""载荷合成：吃 sink 类别软先验 → 一批有序、带对照/通道、自带判定契约的探针。"""
from .core import PATH_SIGNATURES, PayloadSynthesizer
from .types import ProbeSpec

__all__ = ["PayloadSynthesizer", "ProbeSpec", "PATH_SIGNATURES"]
