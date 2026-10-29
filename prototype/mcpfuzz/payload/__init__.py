"""载荷合成：sink + 判定器探针 → 一批有序、自带验证信号的载荷。第一期：命令注入 / SSRF / 路径穿越。"""
from .core import PATH_SIGNATURES, PHASE1_SINKS, PayloadSynthesizer
from .types import Payload

__all__ = ["PayloadSynthesizer", "Payload", "PHASE1_SINKS", "PATH_SIGNATURES"]
