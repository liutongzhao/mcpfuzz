"""Payload-synthesis self-check (pure unit, sends no request, no network): build a classified prior -> inspect the generated probe battery."""
from calchas.oracle import Oracle
from calchas.payload import PayloadSynthesizer
from calchas.sink.types import CI, PT, SSRF, ParamSinkPrior


def show(synth, title, prior):
    print(f"\n===== {title} =====")
    for p in synth.synthesize(prior):
        exp = p.expect[:1] if p.channel == "inband" else "-"
        print(f"  [{p.rank:2d}] {p.vuln_class:18s} {p.channel:12s} {p.technique:22s}")
        print(f"       value = {p.value!r}  expect={exp}  delay={p.delay_target}")


def run() -> int:
    synth = PayloadSynthesizer(Oracle())
    # repo_path classified as PT + CI (handed to git): full battery for both
    show(synth, "repo_path: PT + CI",
         ParamSinkPrior("someTool", "path", "string", classes=[CI, PT],
                        provenance={CI: ["name matched keyword 'path'"], PT: ["name matched keyword 'path'"]}))

    # url classified as SSRF only
    show(synth, "url: SSRF",
         ParamSinkPrior("fetchTool", "url", "string", classes=[SSRF],
                        provenance={SSRF: ["name matched keyword 'url'"]}))

    # no class -> empty; inert parameter -> empty
    assert synth.synthesize(ParamSinkPrior("t", "msg", "string", classes=[])) == []
    assert synth.synthesize(ParamSinkPrior("t", "flag", "boolean", inert=True, inert_reason="boolean")) == []
    print("\nself-check done (generation only, nothing sent)")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
