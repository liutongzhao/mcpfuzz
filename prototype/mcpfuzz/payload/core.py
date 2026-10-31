"""载荷合成：给一个参数的类别软先验 + 判定器，产出一批有序、自带对照/通道的探针。

见 docs/载荷合成模块设计.md。
- 吃 sink 的 class_weights：为每个启用类别按权重分预算生成套件，floor 保每类最小套件；不按单标签门控。
- 每条探针绑定一个 oracle 观测物（oob/inband 需要）或携带对照（timing/differential）。
- 诱饵（回连URL/标记）由判定器铸造，载荷只填入——保持解耦。
"""
from __future__ import annotations

import math

from .batteries import get_battery
from .types import ProbeSpec

# 路径穿越读 /etc/passwd 的稳定特征串（对外兼容旧引用）
PATH_SIGNATURES = ["root:x:0:0:", "root:x:0:0", "daemon:x:"]


def _budget(weight: float, total: int) -> int:
    """权重 → 取 top-N。地板(0.1)也至少取前 2 条（召回下界）；权重越高覆盖越全。"""
    if total <= 0:
        return 0
    return min(max(2, math.ceil(total * weight)), total)


class PayloadSynthesizer:
    def __init__(self, oracle):
        self.oracle = oracle

    def synthesize(self, prior) -> list[ProbeSpec]:
        """prior: sink.ParamSinkPrior。按 class_weights 为每个启用类别分预算、生成探针，合并排序。"""
        if getattr(prior, "inert", False) or not getattr(prior, "class_weights", None):
            return []
        out: list[ProbeSpec] = []
        rank = 0
        for cls in prior.ranked_classes():      # 权重从高到低
            weight = prior.class_weights[cls]
            templates = get_battery(cls)
            if not templates:
                continue
            for tpl in templates[:_budget(weight, len(templates))]:
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
        if channel in ("oob", "inband"):
            probe = self.oracle.new_probe(channel, meta=meta, expect=expect)
            # inband 的 embed 即 token；oob 的 embed 即完整回连 URL
            value = value.replace("{CALLBACK}", probe.embed).replace("{TOKEN}", probe.embed)
            probe.meta["payload"] = value
        return ProbeSpec(
            tool=tool, param_path=param, vuln_class=cls, value=value, channel=channel,
            control=tpl.get("control"), probe=probe,
            expect=(expect or (probe.expect if probe else [])),
            delay_target=tpl.get("delay_target", 0.0), technique=tpl.get("technique", ""))
