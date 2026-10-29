"""载荷合成自测（纯单元，不发请求、不连网络）：构造 sink 标注 → 看生成的载荷。"""
from mcpfuzz.oracle import Oracle
from mcpfuzz.payload import PayloadSynthesizer
from mcpfuzz.sink.types import CI, PT, SSRF, ParamSink, SinkLabel

synth = PayloadSynthesizer(Oracle())


def show(title, ps):
    print(f"\n===== {title} =====")
    for p in synth.synthesize(ps):
        print(f"  [{p.rank:2d}] {p.sink:17s} {p.channel:10s} {p.technique:22s}")
        print(f"       value = {p.value!r}")
        print(f"       probe = {p.probe.token} (expect={p.probe.expect if p.channel=='reflection' else '-'})")


# 命令注入 + 路径穿越（高/低置信，验证排序：高置信 sink 在前）
show("命令注入(high) + 路径穿越(low) 的参数",
     ParamSink("someTool", "arg", "string",
               [SinkLabel(CI, "high", "both", ""), SinkLabel(PT, "low", "llm", "")]))

# SSRF
show("SSRF 参数",
     ParamSink("fetchTool", "url", "string", [SinkLabel(SSRF, "high", "both", "")]))

print("\n自测完成（仅生成，未发送）")
