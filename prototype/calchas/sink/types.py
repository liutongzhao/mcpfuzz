"""Sink-inference data structures and the closed set + class weights (floor + raise).

Design points (see the sink-inference design doc):
- Enumerate at the "injection class / dangerous boundary" closed set, not at the "backend program" level.
- The output is a **soft prior** (one weight per enabled class), not a single hard label; downstream only
  sorts, it does not gate.
- "Floor + raise": every non-inert parameter starts each enabled class at a non-zero floor (fail-open,
  so recall has a lower bound and does not collapse to zero under classifier error); rules / the LLM only
  lift relevant classes up from the floor, combined by max.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Closed set of injection classes (abstracted by "dangerous boundary", no concrete program names)
CI = "command_injection"
AI = "argument_injection"
PT = "path_traversal"
SSRF = "ssrf"
QI = "query_injection"
CODE = "code_injection"
NONE = "none"
SINK_TYPES = {CI, AI, PT, SSRF, QI, CODE, NONE}

# Classes enabled in this phase (a phase-scope config, != a per-parameter gate; QI stays for a later phase).
# CODE (code injection, CWE-94) is enabled: L1 eval-echo reuses the flagship logic, net-new is the L2
# out-of-domain probe + declared_domain + the intent gate.
PHASE1_CLASSES = (CI, AI, PT, SSRF, CODE)

# Weight tiers. The floor keeps every value non-zero (any enabled class gets at least a minimal payload
# budget downstream); a raise only increases, combined by max.
FLOOR = 0.1      # floor: every enabled class of any non-inert parameter is >= this
W_LOW = 0.4      # weak evidence (description hit / LLM low)
W_MED = 0.7      # medium evidence (parameter-name hit / LLM medium)
W_HIGH = 1.0     # strong evidence (LLM high)

CONF_WEIGHT = {"low": W_LOW, "medium": W_MED, "high": W_HIGH}


@dataclass
class Raise:
    """One "raise" of evidence: lift a class to some weight. Comes from a rule or the LLM."""
    cls: str
    weight: float
    source: str      # rule | llm
    reason: str = ""


@dataclass
class ParamSinkPrior:
    """A parameter's soft prior over injection classes.

    class_weights only covers the "enabled classes", and is non-empty only for **non-inert** parameters;
    each value is >= FLOOR. provenance records the evidence for each class lifted above the floor, for
    debugging and reporting.
    """
    tool: str
    param_path: str
    param_type: str
    class_weights: dict = field(default_factory=dict)   # {class: weight>=FLOOR}
    inert: bool = False
    inert_reason: str = ""
    provenance: dict = field(default_factory=dict)      # {class: [evidence str, ...]}
    param: object = None                                 # original catalog.Param (carries pattern/format/length etc., for constraint-aware payloads)
    # Code-injection only: the LLM's paraphrase of the parameter's "declared computation domain" + a quote
    # (forced to quote the description/schema verbatim; empty if none can be cited).
    # Current policy B: annotation for manual dangerous-by-design judgement only, NOT part of the tool's
    # automatic verdict (see the code-injection design doc §5).
    declared_domain: str = ""
    domain_evidence: str = ""

    def ranked_classes(self) -> list[str]:
        """Return the enabled classes from highest to lowest weight (for downstream budget allocation)."""
        return [c for c, _ in sorted(self.class_weights.items(), key=lambda kv: -kv[1])]

    def weight_of(self, cls: str) -> float:
        return self.class_weights.get(cls, 0.0)
