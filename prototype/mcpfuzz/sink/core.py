"""Sink 推断门面：结构预筛 + 地板抬升（规则并集 + 大模型），输出每参数的类别软先验。

见 docs/Sink推断模块设计.md。产出 ParamSinkPrior（class_weights 带地板），下游只排序不闸门。
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .llm import classify_tool
from .rules import rule_raises
from .types import (CONF_WEIGHT, FLOOR, PHASE1_CLASSES, ParamSinkPrior, Raise)


def is_inert(param) -> tuple[bool, str]:
    """结构预筛：仅对**值域封闭、结构上不可能承载注入**的参数做事实性过滤（召回优先，宁放勿误杀）。

    惰性（跳过）：布尔、枚举、元素非字符串的数组。
    其余（字符串/联合/未知/数值标量/含字符串数组/对象）一律进入语义先验——
    数值标量虽多半会被校验挡下，但仍以地板最小预算测试，避免漏掉"宽松校验"的服务端。
    """
    if param.enum:
        return True, "枚举，值域封闭"
    t = param.type
    if t == "boolean":
        return True, "布尔，值域封闭"
    if t == "array":
        it = param.item_type or "unknown"
        if it not in ("string", "union", "unknown"):
            return True, f"数组元素类型 {it}，非字符串"
    return False, ""


def _combine(enabled, rule_rs: list[Raise], llm_rs: list[Raise]):
    """地板 + 抬升：每个启用类别从地板起，被规则/大模型抬升取 max。返回 (weights, provenance)。"""
    weights = {c: FLOOR for c in enabled}
    provenance: dict[str, list] = {}
    for r in rule_rs + llm_rs:
        if r.cls not in weights:
            continue   # 非本阶段启用类别（阶段范围闸门，允许）
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
            # as_completed 边完成边上报：LLM 分类是本阶段最慢的部分，逐工具推进进度条，避免界面像卡死。
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
                    out.append(ParamSinkPrior(tool.name, p.path, p.type, {}, True, reason))
                    continue
                rule_rs = rule_raises(p)
                llm_rs = [Raise(x["type"], CONF_WEIGHT.get(x.get("confidence", "low"), CONF_WEIGHT["low"]),
                                "llm", x.get("evidence", ""))
                          for x in tl.get(p.path, []) if x.get("type") in self.enabled]
                weights, prov = _combine(self.enabled, rule_rs, llm_rs)
                ps = ParamSinkPrior(tool.name, p.path, p.type, weights, False, "", prov)
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
