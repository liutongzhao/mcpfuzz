"""Sink-inference facade: structural pre-filter + floor-and-raise (rule union + LLM), emitting a
per-parameter soft prior over classes.

See the sink-inference design doc. Produces ParamSinkPrior (class_weights with a floor); downstream only
sorts, it does not gate.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .llm import classify_tool
from .rules import rule_raises
from .types import (CONF_WEIGHT, FLOOR, PHASE1_CLASSES, ParamSinkPrior, Raise)


def is_inert(param) -> tuple[bool, str]:
    """Structural pre-filter: only factually filter out parameters whose value domain is closed and that
    structurally cannot carry an injection (recall-first, prefer to keep rather than wrongly drop).

    Inert (skipped): boolean, enum, arrays whose elements are non-string.
    Everything else (string / union / unknown / numeric scalar / array containing strings / object) goes
    into the semantic prior — a numeric scalar is mostly rejected by validation, but is still tested with
    the minimal floor budget, so a server with loose validation is not missed.
    """
    if param.enum:
        return True, "enum, closed value domain"
    t = param.type
    if t == "boolean":
        return True, "boolean, closed value domain"
    if t == "array":
        it = param.item_type or "unknown"
        if it not in ("string", "union", "unknown"):
            return True, f"array element type {it}, non-string"
    return False, ""


def _combine(enabled, rule_rs: list[Raise], llm_rs: list[Raise]):
    """Floor + raise: each enabled class starts at the floor and is lifted by rules/the LLM via max.
    Returns (weights, provenance)."""
    weights = {c: FLOOR for c in enabled}
    provenance: dict[str, list] = {}
    for r in rule_rs + llm_rs:
        if r.cls not in weights:
            continue   # a class not enabled in this phase (phase-scope gate, allowed)
        if r.weight > weights[r.cls]:
            weights[r.cls] = r.weight
        if r.weight > FLOOR:
            provenance.setdefault(r.cls, []).append(f"[{r.source}:{r.weight:.1f}] {r.reason}")
    return weights, provenance


class SinkInferencer:
    def __init__(self, use_llm: bool = True, cache_dir: str | Path | None = None, workers: int = 6,
                 reporter=None, enabled_classes=PHASE1_CLASSES):
        self.use_llm = use_llm
        self.cache_dir = cache_dir
        self.workers = workers
        self.reporter = reporter or _NullReporter()
        self.enabled = tuple(enabled_classes)

    def infer(self, target) -> list[ParamSinkPrior]:
        self.reporter.emit("sink.start", tool_count=len(target.tools))
        llm_map: dict[str, dict] = {}
        if self.use_llm and target.tools:
            def one(tool):
                try:
                    return tool.name, classify_tool(tool, self.cache_dir)
                except Exception:
                    return tool.name, {}
            total = len(target.tools)
            # as_completed reports as it finishes: LLM classification is the slowest part of this phase;
            # advance the progress bar per tool so the UI does not look frozen.
            with ThreadPoolExecutor(min(self.workers, total)) as ex:
                futures = [ex.submit(one, t) for t in target.tools]
                done = 0
                for fut in as_completed(futures):
                    name, res = fut.result()
                    llm_map[name] = res
                    done += 1
                    self.reporter.emit("sink.progress", done=done, total=total, tool=name)

        out: list[ParamSinkPrior] = []
        hot = 0
        for tool in target.tools:
            tl = llm_map.get(tool.name, {})
            for p in tool.params:
                inert, reason = is_inert(p)
                if inert:
                    out.append(ParamSinkPrior(tool.name, p.path, p.type, {}, True, reason, param=p))
                    continue
                rule_rs = rule_raises(p)
                llm_rs = [Raise(x["type"], CONF_WEIGHT.get(x.get("confidence", "low"), CONF_WEIGHT["low"]),
                                "llm", x.get("evidence", ""))
                          for x in tl.get(p.path, []) if x.get("type") in self.enabled]
                weights, prov = _combine(self.enabled, rule_rs, llm_rs)
                ps = ParamSinkPrior(tool.name, p.path, p.type, weights, False, "", prov, param=p)
                # Code-injection declared domain (if the LLM labelled this parameter code_injection and
                # gave a declared_domain): policy B, annotation for manual dangerous-by-design judgement
                # only, not part of the automatic verdict.
                for x in tl.get(p.path, []):
                    if x.get("type") == "code_injection":
                        ps.declared_domain = x.get("declared_domain", "") or ps.declared_domain
                        ps.domain_evidence = x.get("domain_evidence", "") or ps.domain_evidence
                out.append(ps)
                if prov:
                    hot += 1
                    self.reporter.emit("sink.labeled", tool=tool.name, param=p.path,
                                       weights={c: round(w, 2) for c, w in weights.items()},
                                       provenance=prov)
        self.reporter.emit("sink.done", param_count=len(out), hot_count=hot)
        return out


class _NullReporter:
    def emit(self, *a, **k):
        pass
