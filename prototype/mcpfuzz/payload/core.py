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
        if channel in ("oob", "inband", "cross_tool"):
            # cross_tool 也需要一个唯一 token（写入 canary 文件再由读工具读回），按 inband 铸造
            probe = self.oracle.new_probe("oob" if channel == "oob" else "inband", meta=meta, expect=None)
            # inband/cross_tool 的 embed 即 token；oob 的 embed 即完整回连 URL。
            # {TOKEN} → token（即 inband 的 embed）；{CALLBACK} → oob 的完整回连 URL。
            value = value.replace("{CALLBACK}", probe.embed).replace("{TOKEN}", probe.token)
            # 期望签名也做占位符替换：求值型回显用 "{TOKEN}1681" 这种"执行后才出现"的形态，
            # 可区分"真执行"与"输入被原样回显"（后者只会出现 {TOKEN}$((41*41))）。
            if expect:
                expect = [str(e).replace("{TOKEN}", probe.token).replace("{CALLBACK}", probe.embed)
                          for e in expect]
            else:
                expect = [probe.token]
            probe.expect = expect
            probe.meta["payload"] = value
        return ProbeSpec(
            tool=tool, param_path=param, vuln_class=cls, value=value, channel=channel,
            control=tpl.get("control"), probe=probe, expect=(expect or []),
            delay_target=tpl.get("delay_target", 0.0), technique=tpl.get("technique", ""),
            reflection_safe=tpl.get("reflection_safe", True))
