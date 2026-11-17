"""Payload-layer data structure: the probe (ProbeSpec) — the interface object between payload synthesis
and verdict.

See the payload-synthesis design doc. One probe = active payload + benign control + vuln class + observation channel
+ hit criterion + observable.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ProbeSpec:
    tool: str
    param_path: str
    vuln_class: str          # command_injection / argument_injection / path_traversal / ssrf ...
    value: str               # active payload: the final string placed into the parameter (may already embed an oracle decoy)
    channel: str             # observation channel: oob / inband / timing / differential
    control: str | None = None   # benign control value (required for timing/differential; may be empty for direct-evidence types, falling back to the baseline)
    probe: object = None     # observable minted by the oracle (needed for oob/inband; None for timing/differential)
    expect: list = field(default_factory=list)   # signature(s) to match in the response for inband (default [token])
    delay_target: float = 0.0   # timing: expected extra delay (seconds)
    technique: str = ""      # for reporting, e.g. 'ci:;echo' / 'pt:../etc/passwd'
    rank: int = 0            # lower = sent earlier, supports early-stop
    reflection_safe: bool = True   # whether an inband hit is "reflection-immune": the expected signature cannot be produced by the input being echoed verbatim.
    #   False (e.g. AI unknown-option, where the token is in the input itself) -> a hit requires a corresponding error fingerprint to corroborate before it counts as confirmed, otherwise it is only weak evidence.
    placement: str = "value"   # payload placement for object-typed parameters: value (in the map's value) / key (in the map's key)
    target_scope: str = "public"   # which target class the SSRF payload hits: public (internet / our own callback collector) /
    #   internal (intranet / loopback / cloud metadata). The trust-boundary judgement uses this: only reaching an internal target counts as SSRF evidence;
    #   egress to the public internet is the intended function of URL-fetching tools and does not by itself constitute a vulnerability.
    tier: str = ""   # code-injection impact tier (not a confirmation gate, policy ①): "L1"=arithmetic eval (impact=arithmetic_eval) /
    #   "L2"=out-of-domain eval (template delimiter / function-call echo, impact=rce). Any hit confirms; left empty for other classes.
