"""Step-three entry: connect to the target -> get the tool catalog -> infer each parameter's sink, print and save.

Usage:
  python dump_sinks.py <URL | config.json> [name]
  python dump_sinks.py <...> --no-llm          # rule layer only (comparison)
Results are saved to out/<server>_sinks.json.
"""
import json
import re
import sys
from pathlib import Path

from calchas.driver import fetch_catalog_sync
from calchas.sink import SinkInferencer
from calchas.targetcfg import resolve_target

OUT = Path(__file__).resolve().parent / "out"


def main():
    args = [a for a in sys.argv[1:] if a != "--no-llm"]
    use_llm = "--no-llm" not in sys.argv
    if not args:
        sys.exit("usage: python dump_sinks.py <URL | config.json> [name] [--no-llm]")
    url, headers = resolve_target(args[0], args[1] if len(args) > 1 else None)

    print(f"connecting {url} ..." + (" (with auth header)" if headers else ""))
    target = fetch_catalog_sync(url, headers)
    print(f"server: {target.server_name} {target.server_version}  tools: {len(target.tools)}")
    print(f"inference: {'rules + LLM' if use_llm else 'rules only'}\n")

    inferencer = SinkInferencer(use_llm=use_llm, cache_dir=OUT / ".sink_cache")
    results = inferencer.infer(target)

    hot = [r for r in results if not r.inert and r.provenance]
    for r in hot:
        tags = ", ".join(f"{c}({r.class_weights.get(c)})" for c in r.provenance)
        print(f"● {r.tool}.{r.param_path}  [{r.param_type}]")
        print(f"    → {tags}")
        for c, evs in r.provenance.items():
            for ev in evs:
                print(f"      · {c}: {ev}")

    total_params = len(results)
    print(f"\nparameters with sink candidates: {len(hot)} / {total_params}")

    OUT.mkdir(exist_ok=True)
    safe = re.sub(r"[^\w.-]", "_", (target.server_name or "server"))
    path = OUT / f"{safe}_sinks.json"
    path.write_text(json.dumps(
        [{"tool": r.tool, "param_path": r.param_path, "param_type": r.param_type,
          "inert": r.inert, "class_weights": r.class_weights, "provenance": r.provenance}
         for r in results],
        ensure_ascii=False, indent=2))
    print(f"saved: {path}")


if __name__ == "__main__":
    main()
