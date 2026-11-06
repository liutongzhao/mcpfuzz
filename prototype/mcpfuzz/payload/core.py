"""载荷合成：给一个参数的类别软先验 + 判定器，产出一批有序、自带对照/通道的探针。

见 docs/载荷合成模块设计.md。
- 吃 sink 的 class_weights：为每个启用类别按权重分预算生成套件，floor 保每类最小套件；不按单标签门控。
- 每条探针绑定一个 oracle 观测物（oob/inband 需要）或携带对照（timing/differential）。
- 诱饵（回连URL/标记）由判定器铸造，载荷只填入——保持解耦。
"""
from __future__ import annotations

import math

from mcpfuzz.sink.types import W_MED

from .batteries import get_battery
from .types import ProbeSpec

# 路径穿越读 /etc/passwd 的稳定特征串（对外兼容旧引用）
PATH_SIGNATURES = ["root:x:0:0:", "root:x:0:0", "daemon:x:"]


def _select_templates(templates: list, weight: float) -> list:
    """选该类要发的载荷。按「证据类发全套 + 否则通道分层预算」，**保证不把整条确认通道砍掉**。

    - 有真证据的类（权重 ≥ W_MED，即大模型 medium/high 或规则参数名命中）：发**全套**，
      回显/时延/带外各通道齐全（否则像 eval/exec 这种无回显 sink 只靠回显会漏判）。
    - 否则按预算 `ceil(总数×权重)`（地板 ≥2 条，保召回下界），但**先给每个出现的确认通道留 1 条**
      （inband/timing/oob/differential/cross_tool/path_confine），再按原序补足预算——避免预算把
      timing/带外这类正交通道整条切掉（这正是 vegalite/Jij 只判疑似的根因）。
    """
    total = len(templates)
    if total == 0:
        return []
    if weight >= W_MED:
        return list(templates)
    budget = min(max(2, math.ceil(total * weight)), total)
    picked: list[int] = []
    pickset: set[int] = set()
    seen_ch: set[str] = set()
    for i, t in enumerate(templates):          # 每个通道的第一条，保证通道覆盖
        ch = t.get("channel", "")
        if ch not in seen_ch:
            seen_ch.add(ch)
            picked.append(i)
            pickset.add(i)
    for i in range(total):                      # 按原序补足到预算
        if len(picked) >= budget:
            break
        if i not in pickset:
            picked.append(i)
            pickset.add(i)
    return [templates[i] for i in sorted(picked)]


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
            for tpl in _select_templates(templates, weight):
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
        if channel in ("oob", "inband", "cross_tool", "path_confine"):
            # cross_tool 也需要一个唯一 token（写入 canary 文件再由读工具读回），按 inband 铸造
            # path_confine 用 token 作越界路径的唯一 canary 名（{TOKEN}），便于识别回显/写落点，按 inband 铸造
            probe = self.oracle.new_probe("oob" if channel == "oob" else "inband", meta=meta, expect=None)
            # inband/cross_tool 的 embed 即 token；oob 的 embed 即完整回连 URL。
            # {TOKEN} → token（即 inband 的 embed）；{CALLBACK} → oob 的完整回连 URL。
            # {CALLBACK_HOST} → 去掉 scheme 的回连目标（host:port/token），token 仍在 path，
            #   故带外命中依旧可归因；用于 SSRF 的占位感知形态（host 段注入/协议相对/@ 混淆/无 scheme）。
            host_embed = probe.embed.split("://", 1)[-1] if channel == "oob" else probe.embed
            value = (value.replace("{CALLBACK_HOST}", host_embed)
                          .replace("{CALLBACK}", probe.embed)
                          .replace("{TOKEN}", probe.token))
            # 期望签名也做占位符替换：求值型回显用 "{TOKEN}1681" 这种"执行后才出现"的形态，
            # 可区分"真执行"与"输入被原样回显"（后者只会出现 {TOKEN}$((41*41))）。
            if expect:
                expect = [str(e).replace("{TOKEN}", probe.token)
                          .replace("{CALLBACK_HOST}", host_embed).replace("{CALLBACK}", probe.embed)
                          for e in expect]
            else:
                expect = [probe.token]
            probe.expect = expect
            probe.meta["payload"] = value
        return ProbeSpec(
            tool=tool, param_path=param, vuln_class=cls, value=value, channel=channel,
            control=tpl.get("control"), probe=probe, expect=(expect or []),
            delay_target=tpl.get("delay_target", 0.0), technique=tpl.get("technique", ""),
            reflection_safe=tpl.get("reflection_safe", True),
            target_scope=tpl.get("target_scope", "public"),
            tier=tpl.get("tier", ""))
