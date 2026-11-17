"""Adjudication: produce a verdict from whether there was a hit."""
from __future__ import annotations

from dataclasses import dataclass, field

from .probe import Hit, Probe

CONFIRMED = "confirmed"        # confirmed: an unnatural-signal hit on the unique token
NOT_TRIGGERED = "not_triggered"


@dataclass
class Finding:
    status: str
    channel: str
    tool: str | None = None
    param: str | None = None
    payload: str | None = None
    evidence: dict = field(default_factory=dict)
    repro: str | None = None


def decide(probe: Probe, hit: Hit | None) -> Finding:
    m = probe.meta
    if hit is not None:
        return Finding(
            status=CONFIRMED, channel=probe.channel,
            tool=m.get("tool"), param=m.get("param"), payload=m.get("payload"),
            evidence=hit.evidence,
            repro=f"sent payload to parameter {m.get('param')} of tool {m.get('tool')}: {m.get('payload')!r}",
        )
    return Finding(status=NOT_TRIGGERED, channel=probe.channel,
                   tool=m.get("tool"), param=m.get("param"), payload=m.get("payload"))
