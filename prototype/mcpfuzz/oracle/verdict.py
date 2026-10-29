"""裁决：由命中与否给出判定结论。"""
from __future__ import annotations

from dataclasses import dataclass, field

from .probe import Hit, Probe

CONFIRMED = "confirmed"        # 确认：唯一 token 的非自然信号命中
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
            repro=f"对工具 {m.get('tool')} 的参数 {m.get('param')} 发送载荷：{m.get('payload')!r}",
        )
    return Finding(status=NOT_TRIGGERED, channel=probe.channel,
                   tool=m.get("tool"), param=m.get("param"), payload=m.get("payload"))
