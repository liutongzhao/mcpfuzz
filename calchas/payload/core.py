"""Payload synthesis: given a parameter's class soft prior + the oracle, produce an ordered batch of
probes that carry their own control/channel.

See the payload-synthesis design doc.
- Consumes the sink's class_weights: generate a battery per enabled class, budgeted by weight; the floor
  keeps a minimal battery per class; no gating by single label.
- Each probe binds one oracle observable (needed for oob/inband) or carries a control (timing/differential).
- Decoys (callback URL / marker) are minted by the oracle, the payload only fills them in — keeping it decoupled.
"""
from __future__ import annotations

import math

from calchas.sink.types import W_MED

from .batteries import get_battery
from .types import ProbeSpec

# Stable signature strings for a path-traversal read of /etc/passwd (kept for external legacy references)
PATH_SIGNATURES = ["root:x:0:0:", "root:x:0:0", "daemon:x:"]


def _select_templates(templates: list, weight: float) -> list:
    """Pick which payloads of this class to send. "Full battery for evidence-backed classes, otherwise a
    per-channel budgeted set", **guaranteeing no confirmation channel is cut entirely**.

    - Classes with real evidence (weight >= W_MED, i.e. LLM medium/high or a rule parameter-name hit):
      send the **full** battery, with reflection/timing/OOB channels all present (otherwise a no-echo sink
      like eval/exec, relying on reflection alone, would be missed).
    - Otherwise budget by `ceil(total x weight)` (floor >=2, to keep a recall lower bound), but **first
      reserve 1 for each confirmation channel present** (inband/timing/oob/differential/cross_tool/
      path_confine), then fill up to budget in original order — so the budget does not cut an orthogonal
      channel like timing/OOB entirely (which was exactly why vegalite/Jij only scored suspected).
    """
    total = len(templates)
    if total == 0:
        return []
    if weight >= W_MED:
        return list(templates)
    budget = min(max(2, math.ceil(total * weight)), total)
    picked: list[int] = []
    pickset: set[int] = set()
    seen_ch: set[str] = set()
    for i, t in enumerate(templates):          # first of each channel, to guarantee channel coverage
        ch = t.get("channel", "")
        if ch not in seen_ch:
            seen_ch.add(ch)
            picked.append(i)
            pickset.add(i)
    for i in range(total):                      # fill up to budget in original order
        if len(picked) >= budget:
            break
        if i not in pickset:
            picked.append(i)
            pickset.add(i)
    return [templates[i] for i in sorted(picked)]


class PayloadSynthesizer:
    def __init__(self, oracle):
        self.oracle = oracle

    def synthesize(self, prior) -> list[ProbeSpec]:
        """prior: sink.ParamSinkPrior. Budget per enabled class by class_weights, generate probes, merge and sort."""
        if getattr(prior, "inert", False) or not getattr(prior, "class_weights", None):
            return []
        out: list[ProbeSpec] = []
        rank = 0
        for cls in prior.ranked_classes():      # highest to lowest weight
            weight = prior.class_weights[cls]
            templates = get_battery(cls)
            if not templates:
                continue
            for tpl in _select_templates(templates, weight):
                ps = self._build(prior.tool, prior.param_path, cls, tpl)
                ps.rank = rank
                rank += 1
                out.append(ps)
        return out

    def _build(self, tool, param, cls, tpl) -> ProbeSpec:
        channel = tpl["channel"]
        value = tpl["value"]
        expect = tpl.get("expect")
        probe = None
        meta = {"tool": tool, "param": param, "sink": cls, "technique": tpl.get("technique", "")}
        if channel in ("oob", "inband", "cross_tool", "path_confine"):
            # cross_tool also needs a unique token (write a canary file, then read it back via a read tool), minted as inband.
            # path_confine uses the token as the unique canary name of the out-of-bounds path ({TOKEN}), to identify the echo/write landing spot, minted as inband.
            probe = self.oracle.new_probe("oob" if channel == "oob" else "inband", meta=meta, expect=None)
            # For inband/cross_tool, embed is the token; for oob, embed is the full callback URL.
            # {TOKEN} -> token (i.e. the inband embed); {CALLBACK} -> the full oob callback URL.
            # {CALLBACK_HOST} -> the callback target with the scheme stripped (host:port/token); the token is
            #   still in the path, so an OOB hit can still be attributed; used for SSRF's placement-aware forms
            #   (host-segment injection / protocol-relative / @ obfuscation / scheme-less).
            host_embed = probe.embed.split("://", 1)[-1] if channel == "oob" else probe.embed
            value = (value.replace("{CALLBACK_HOST}", host_embed)
                          .replace("{CALLBACK}", probe.embed)
                          .replace("{TOKEN}", probe.token))
            # The expected signature is also placeholder-substituted: an eval-type echo uses a form like
            # "{TOKEN}1681" that "appears only after execution", distinguishing "truly executed" from "input
            # echoed verbatim" (the latter only ever produces {TOKEN}$((41*41))).
            if expect:
                expect = [str(e).replace("{TOKEN}", probe.token)
                          .replace("{CALLBACK_HOST}", host_embed).replace("{CALLBACK}", probe.embed)
                          for e in expect]
            else:
                expect = [probe.token]
            probe.expect = expect
            probe.meta["payload"] = value
        return ProbeSpec(
            tool=tool, param_path=param, vuln_class=cls, value=value, channel=channel,
            control=tpl.get("control"), probe=probe, expect=(expect or []),
            delay_target=tpl.get("delay_target", 0.0), technique=tpl.get("technique", ""),
            reflection_safe=tpl.get("reflection_safe", True),
            target_scope=tpl.get("target_scope", "public"),
            tier=tpl.get("tier", ""))
