"""Payload synthesis: consume the sink-class soft prior -> an ordered batch of probes, each carrying a
control/channel and a self-contained verdict contract."""
from .core import PATH_SIGNATURES, PayloadSynthesizer
from .types import ProbeSpec

__all__ = ["PayloadSynthesizer", "ProbeSpec", "PATH_SIGNATURES"]
