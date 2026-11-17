"""Base data structures for probes and hit evidence, plus token minting and the registry."""
from __future__ import annotations

import secrets
import time

from calchas.__about__ import TOKEN_PREFIX
from dataclasses import dataclass, field


def mint_token() -> str:
    """Generate a token that is unique, cannot occur naturally, is URL/shell-safe, and matchable in text."""
    return TOKEN_PREFIX + secrets.token_hex(5)


@dataclass
class Probe:
    token: str
    channel: str                       # "oob" | "reflection"
    embed: str                         # observable handed to the payload layer (callback URL / reflected marker)
    meta: dict = field(default_factory=dict)   # provenance: tool/param/payload etc.
    expect: list = field(default_factory=list) # strings the reflection channel matches in the response (default [token])
    created_at: float = field(default_factory=time.time)


@dataclass
class Hit:
    token: str
    channel: str
    time: str | None = None
    evidence: dict = field(default_factory=dict)


class ProbeRegistry:
    """Registry of token -> Probe, for provenance and evidence retention."""

    def __init__(self):
        self._probes: dict[str, Probe] = {}

    def add(self, probe: Probe):
        self._probes[probe.token] = probe

    def get(self, token: str) -> Probe | None:
        return self._probes.get(token)

    def all(self) -> list[Probe]:
        return list(self._probes.values())
