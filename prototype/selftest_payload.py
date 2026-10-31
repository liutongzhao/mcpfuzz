"""载荷合成自测（纯单元，不发请求、不连网络）：构造类别软先验 → 看生成的探针套件。"""
from mcpfuzz.oracle import Oracle
from mcpfuzz.payload import PayloadSynthesizer
from mcpfuzz.sink.types import AI, CI, FLOOR, PT, SSRF, ParamSinkPrior

synth = PayloadSynthesizer(Oracle())


def show(title, prior):
    print(f"\n===== {title} =====")
    for p in synth.synthesize(prior):
        exp = p.expect[:1] if p.channel == "inband" else "-"
        print(f"  [{p.rank:2d}] {p.vuln_class:18s} {p.channel:12s} {p.technique:22s}")
        print(f"       value = {p.value!r}  expect={exp}  delay={p.delay_target}")


# path 参数：PT 高(0.7)、其余地板(0.1) —— 复刻 git_tag.path：CI 地板也应出若干探针（不漏）
show("path：PT 高 + CI/AI/SSRF 地板",
     ParamSinkPrior("someTool", "path", "string",
                    {CI: FLOOR, AI: FLOOR, PT: 0.7, SSRF: FLOOR}, False, "", {PT: ["rule"]}))

# SSRF 高
show("url：SSRF 高",
     ParamSinkPrior("fetchTool", "url", "string",
                    {CI: FLOOR, AI: FLOOR, PT: FLOOR, SSRF: 1.0}, False, "", {SSRF: ["rule"]}))

# 惰性参数 → 空
assert synth.synthesize(ParamSinkPrior("t", "flag", "boolean", {}, True, "布尔")) == []
print("\n自测完成（仅生成，未发送）")
