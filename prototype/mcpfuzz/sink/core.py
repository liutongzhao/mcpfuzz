"""Sink 推断门面：合并规则层与大模型层，输出每个参数的 sink 标注。"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .llm import classify_tool
from .rules import rule_sinks
from .types import ParamSink, SinkLabel


def _merge(rules: list[SinkLabel], llms: list[SinkLabel]) -> list[SinkLabel]:
    by: dict[str, SinkLabel] = {}
    for lab in rules + llms:
        cur = by.get(lab.type)
        if cur is None:
            by[lab.type] = lab
            continue
        sources = {cur.source, lab.source}
        source = "both" if ("rule" in sources and "llm" in sources) else cur.source
        confidence = "high" if (source == "both" or "high" in (cur.confidence, lab.confidence)) else "low"
        reason = (lab.reason if lab.source == "llm" else cur.reason) or cur.reason or lab.reason
        by[lab.type] = SinkLabel(lab.type, confidence, source, reason)
    return list(by.values())


class SinkInferencer:
    def __init__(self, use_llm: bool = True, cache_dir: str | Path | None = None, workers: int = 6,
                reporter=None):
        self.use_llm = use_llm
        self.cache_dir = cache_dir
        self.workers = workers
        self.reporter = reporter or _NullReporter()

    def infer(self, target) -> list[ParamSink]:
        self.reporter.emit("sink.start", tool_count=len(target.tools))
        llm_map: dict[str, dict] = {}
        if self.use_llm and target.tools:
            def one(tool):
                try:
                    return tool.name, classify_tool(tool, self.cache_dir)
                except Exception:
                    return tool.name, {}
            with ThreadPoolExecutor(min(self.workers, len(target.tools))) as ex:
                llm_map = dict(ex.map(one, target.tools))

        out: list[ParamSink] = []
        hot = 0
        for tool in target.tools:
            tl = llm_map.get(tool.name, {})
            for p in tool.params:
                rules = rule_sinks(p)
                llms = [SinkLabel(x["type"], x.get("confidence", "low"), "llm", x.get("reason", ""))
                        for x in tl.get(p.path, [])]
                merged = _merge(rules, llms)
                ps = ParamSink(tool.name, p.path, p.type, merged)
                out.append(ps)
                if merged:
                    hot += 1
                    self.reporter.emit("sink.labeled", tool=tool.name, param=p.path,
                                       sinks=[vars(s) for s in merged])
        self.reporter.emit("sink.done", param_count=len(out), hot_count=hot)
        return out


class _NullReporter:
    def emit(self, *a, **k):
        pass
