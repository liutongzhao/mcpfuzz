"""Sink-inference facade: structural pre-filter, then ONE classifier (LLM or keyword, mutually exclusive)
decides which dangerous operations each parameter reaches; operations expand to the tested injection classes.

See the sink-inference design doc (2026-11-18 redesign). Deterministic multi-label classification, no
weights: a class is either tested (full battery downstream) or not tested.
- LLM on  (use_llm=True) : semantic classification by the LLM (sink/llm.py).
- LLM off (use_llm=False): keyword classification by name-matching the induced lexicon (sink/rules.py).
The two arms are alternatives selected by the switch (the ablation), never unioned.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .llm import classify_tool
from .rules import keyword_operations
from .types import PHASE1_CLASSES, ParamSinkPrior, operations_to_classes


def is_inert(param) -> tuple[bool, str]:
    """Structural pre-filter: drop only parameters whose value domain is closed and that structurally
    cannot carry an injection (recall-first: prefer to keep rather than wrongly drop).

    Inert (skipped): boolean, enum, arrays whose elements are non-string.
    Everything else (string / union / unknown / numeric scalar / array of strings / object) is classified.
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
                    return tool.name, classify_tool(tool, target, self.cache_dir)
                except Exception:
                    return tool.name, {}
            total = len(target.tools)
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
                    out.append(ParamSinkPrior(tool.name, p.path, p.type, inert=True, inert_reason=reason, param=p))
                    continue
                if self.use_llm:
                    info = tl.get(p.path, {}) or {}
                    ops = list(info.get("operations", []))
                    ev = info.get("evidence", {}) or {}
                    decl, dev = info.get("declared_domain", ""), info.get("domain_evidence", "")
                else:
                    ops_set, ev = keyword_operations(p)
                    ops = list(ops_set)
                    decl = dev = ""
                classes = operations_to_classes(ops, self.enabled)
                prov = self._provenance(classes, ops, ev)
                ps = ParamSinkPrior(tool.name, p.path, p.type, classes=classes, provenance=prov,
                                    operations=ops, param=p, declared_domain=decl, domain_evidence=dev)
                out.append(ps)
                if classes:
                    hot += 1
                    self.reporter.emit("sink.labeled", tool=tool.name, param=p.path,
                                       classes=classes, operations=ops, provenance=prov)
        self.reporter.emit("sink.done", param_count=len(out), hot_count=hot)
        return out

    @staticmethod
    def _provenance(classes, ops, evidence) -> dict:
        """Attach each class's evidence: the quote/keyword of the operation it came from."""
        from .types import OP_TO_CLASSES
        prov: dict[str, list] = {}
        for op in ops:
            e = evidence.get(op)
            if not e:
                continue
            items = e if isinstance(e, list) else [e]
            for cls in OP_TO_CLASSES.get(op, ()):
                if cls in classes:
                    prov.setdefault(cls, []).extend(str(x) for x in items)
        return prov


class _NullReporter:
    def emit(self, *a, **k):
        pass
