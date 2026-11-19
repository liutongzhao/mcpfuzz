"""Sink-inference data structures: the closed set of injection classes, the four dangerous-operation
labels the classifier decides, and the operation -> class mapping.

Design (see the sink-inference design doc; 2026-11-18 redesign):
- Stage 1 is a **deterministic multi-label classification**, not scoring. For each (non-inert) parameter
  the classifier decides which of four dangerous OPERATIONS the value can reach; each operation expands
  to the injection classes that get tested. No weights, no floor, no per-class budget — a class is either
  tested (full battery) or not tested at all.
- Command injection and argument injection are merged under one operation ("the value is handed to an
  external program"), because black-box observation cannot tell whether the value is spliced into a shell
  string or passed as a separate argv — only the fact that a program is invoked is visible.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Closed set of injection classes (the unit the payload batteries are keyed by)
CI = "command_injection"
AI = "argument_injection"
PT = "path_traversal"
SSRF = "ssrf"
QI = "query_injection"
CODE = "code_injection"
NONE = "none"
SINK_TYPES = {CI, AI, PT, SSRF, QI, CODE, NONE}

# Classes enabled in this phase (QI stays for a later phase).
PHASE1_CLASSES = (CI, AI, PT, SSRF, CODE)

# The four dangerous operations the classifier decides (both the LLM and the keyword classifier speak
# in these terms), and what each expands to. This mapping is the whole "operation -> what to test" table.
OP_EXTERNAL = "external_program"   # value handed to an invoked external program
OP_FILE = "file_path"              # value becomes a filesystem path the server reads/writes
OP_NETWORK = "network_address"     # value becomes an address the server requests
OP_CODE = "code_eval"              # value is evaluated as code / a template
OPERATIONS = (OP_EXTERNAL, OP_FILE, OP_NETWORK, OP_CODE)

OP_TO_CLASSES = {
    OP_EXTERNAL: (CI, AI),
    OP_FILE: (PT,),
    OP_NETWORK: (SSRF,),
    OP_CODE: (CODE,),
}

# Fixed display/budget order for classes (stable output; no longer a priority by score).
_CLASS_ORDER = {c: i for i, c in enumerate((CI, AI, PT, SSRF, CODE, QI))}


def operations_to_classes(ops, enabled) -> list[str]:
    """Expand a set/iterable of operation labels into the enabled injection classes, in fixed order."""
    enabled = set(enabled)
    out = {c for op in ops for c in OP_TO_CLASSES.get(op, ()) if c in enabled}
    return sorted(out, key=lambda c: _CLASS_ORDER.get(c, 99))


@dataclass
class ParamSinkPrior:
    """A parameter's stage-1 classification result.

    classes: the injection classes this parameter is classified into (= will be tested with the full
    battery). Empty for an inert parameter, or for a non-inert parameter the classifier decided reaches
    no dangerous operation ("none") — that is a definite conclusion, not a failure.
    operations: the raw operation labels the classifier decided (for reporting / ablation).
    provenance: {class: [evidence str]} — which signal led to each class (LLM quote or matched keyword).
    """
    tool: str
    param_path: str
    param_type: str
    classes: list = field(default_factory=list)          # tested injection classes (no weights)
    inert: bool = False
    inert_reason: str = ""
    provenance: dict = field(default_factory=dict)        # {class: [evidence str, ...]}
    operations: list = field(default_factory=list)        # raw operation labels decided
    param: object = None                                  # original catalog.Param (carries constraints)
    # Code-injection only: the LLM's paraphrase of the parameter's declared computation domain + a quote.
    # Annotation for manual dangerous-by-design review only, NOT part of the automatic verdict.
    declared_domain: str = ""
    domain_evidence: str = ""

    def ranked_classes(self) -> list[str]:
        """The tested classes, in fixed order (kept for downstream call sites)."""
        return list(self.classes)

    def has_class(self, cls: str) -> bool:
        return cls in self.classes
