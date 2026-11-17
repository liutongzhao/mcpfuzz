"""Payload-synthesis self-check (pure unit, sends no request, no network): build a class soft prior -> inspect the generated probe battery."""
from calchas.oracle import Oracle
from calchas.payload import PayloadSynthesizer
from calchas.sink.types import AI, CI, FLOOR, PT, SSRF, ParamSinkPrior


def show(synth, title, prior):
    print(f"\n===== {title} =====")
    for p in synth.synthesize(prior):
        exp = p.expect[:1] if p.channel == "inband" else "-"
        print(f"  [{p.rank:2d}] {p.vuln_class:18s} {p.channel:12s} {p.technique:22s}")
        print(f"       value = {p.value!r}  expect={exp}  delay={p.delay_target}")


def run() -> int:
    synth = PayloadSynthesizer(Oracle())
    # path parameter: PT high (0.7), the rest at the floor (0.1) — mirroring git_tag.path: the CI floor should also emit a few probes (no miss)
    show(synth, "path: PT high + CI/AI/SSRF floor",
         ParamSinkPrior("someTool", "path", "string",
                        {CI: FLOOR, AI: FLOOR, PT: 0.7, SSRF: FLOOR}, False, "", {PT: ["rule"]}))

    # SSRF high
    show(synth, "url: SSRF high",
         ParamSinkPrior("fetchTool", "url", "string",
                        {CI: FLOOR, AI: FLOOR, PT: FLOOR, SSRF: 1.0}, False, "", {SSRF: ["rule"]}))

    # inert parameter -> empty
    assert synth.synthesize(ParamSinkPrior("t", "flag", "boolean", {}, True, "boolean")) == []
    print("\nself-check done (generation only, nothing sent)")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
