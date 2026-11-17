"""Orchestrator data structures: call plan, execution result."""
from __future__ import annotations

from dataclasses import dataclass, field

# Five-state verdict (see the verdict-methodology doc)
CONFIRMED = "confirmed"        # hard evidence appeared, or provable on retest -> confirmed vulnerability
SUSPECTED = "suspected"        # only weak evidence (error fingerprint / SSRF callback not crossing the boundary) -> suspected, pending manual review
LIKELY_CLEAN = "likely_clean"  # there is evidence the sink was reached, but the full battery got no hit -> likely no vulnerability
UNREACHED = "unreached"        # the payloads were sent, but all were rejected/errored by the target tool and the baseline is unreachable -> the sink was probably not reached
SKIPPED = "skipped"            # a tool-side reason meant no valid test was ever sent: plan unreachable / prerequisite step errored / session failure /
                               # failure to resolve the target's arguments. This does NOT equal "no vulnerability"; in statistics it must be kept separate from UNREACHED.

# Sink marker for availability / denial-of-service observation. A crash is not a per-parameter verdict but a
# whole-tool finding of "the server was beaten to unresponsiveness after the full battery" (see the
# vuln-types / detection-techniques doc, class 6). Carried by a separate sink value so that in statistics and
# reporting it can be pulled out of the per-param five-state, not polluting parameter coverage.
DOS = "denial_of_service"


@dataclass
class Step:
    step: int
    tool: str
    args: dict                 # {param: {"src":"literal","value":..} | {"src":"from_step","step":n,"extract":".."}}


@dataclass
class Plan:
    steps: list                # list[Step], the last step is the target tool
    reachable: bool = True
    note: str = ""


@dataclass
class Finding:
    tool: str
    param: str
    sink: str
    status: str                # CONFIRMED / LIKELY_CLEAN / UNREACHED
    payload: str = ""
    channel: str = ""
    evidence: dict = field(default_factory=dict)
    sequence: list = field(default_factory=list)   # reproducible sequence (prerequisite calls + the hitting payload)
    note: str = ""
