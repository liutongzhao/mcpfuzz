"""Detection entry: connect to the target -> list catalog -> infer sinks -> orchestrate attack sequence -> verdict -> report.

Usage:
  python run_detect.py <URL | config.json> [name] [--tool TOOL] [--no-llm-sink]
  --tool is repeatable, restricting to certain tools (for debugging); --no-llm-sink makes sink inference use rules only.
Results are saved to out/<server>_findings.json.
"""
import json
import re
import sys
from pathlib import Path

from calchas.driver import fetch_catalog_sync
from calchas.oracle import Oracle
from calchas.orchestrator import CONFIRMED, LIKELY_CLEAN, UNREACHED, Orchestrator
from calchas.sink import SinkInferencer
from calchas.targetcfg import resolve_target

OUT = Path(__file__).resolve().parent / "out"


def main():
    argv = sys.argv[1:]
    only = set()
    while "--tool" in argv:
        i = argv.index("--tool")
        only.add(argv[i + 1])
        del argv[i:i + 2]
    use_llm_sink = "--no-llm-sink" not in argv
    argv = [a for a in argv if a != "--no-llm-sink"]
    if not argv:
        sys.exit("usage: python run_detect.py <URL | config.json> [name] [--tool NAME] [--no-llm-sink]")

    url, headers = resolve_target(argv[0], argv[1] if len(argv) > 1 else None)
    print(f"connecting {url} ..." + (" (with auth header)" if headers else ""))
    catalog = fetch_catalog_sync(url, headers)
    print(f"server: {catalog.server_name} {catalog.server_version}  tools: {len(catalog.tools)}")

    print("inferring sinks ...")
    param_sinks = SinkInferencer(use_llm=use_llm_sink, cache_dir=OUT / ".sink_cache").infer(catalog)

    oracle = Oracle()
    orch = Orchestrator(url, headers, catalog, oracle, cache_dir=OUT)
    print("starting detection" + (f" (only {sorted(only)})" if only else "") + " ...")
    findings = orch.run(param_sinks, only_tools=only or None)

    confirmed = [f for f in findings if f.status == CONFIRMED]
    print("\n================ detection results ================")
    print(f"confirmed {len(confirmed)} | likely clean {sum(f.status==LIKELY_CLEAN for f in findings)} "
          f"| unreached {sum(f.status==UNREACHED for f in findings)} | total {len(findings)}")
    for f in confirmed:
        print(f"\n● [CONFIRMED] {f.tool}.{f.param}  ({f.sink}, channel {f.channel})")
        print(f"    payload: {f.payload!r}")
        print(f"    evidence: {f.evidence}")

    OUT.mkdir(exist_ok=True)
    safe = re.sub(r"[^\w.-]", "_", (catalog.server_name or "server"))
    path = OUT / f"{safe}_findings.json"
    path.write_text(json.dumps([vars(f) for f in findings], ensure_ascii=False, indent=2))
    print(f"\nsaved: {path}")


if __name__ == "__main__":
    main()
