"""第三步入口：连接目标 → 取工具清单 → 推断每个参数的 sink，打印并保存。

用法：
  python dump_sinks.py <URL | config.json> [名称]
  python dump_sinks.py <...> --no-llm          # 只用规则层（对照）
结果保存到 out/<server>_sinks.json。
"""
import json
import re
import sys
from pathlib import Path

from mcpfuzz.driver import fetch_catalog_sync
from mcpfuzz.sink import SinkInferencer
from mcpfuzz.targetcfg import resolve_target

OUT = Path(__file__).resolve().parent / "out"


def main():
    args = [a for a in sys.argv[1:] if a != "--no-llm"]
    use_llm = "--no-llm" not in sys.argv
    if not args:
        sys.exit("用法: python dump_sinks.py <URL | config.json> [名称] [--no-llm]")
    url, headers = resolve_target(args[0], args[1] if len(args) > 1 else None)

    print(f"连接 {url} …" + ("（带鉴权头）" if headers else ""))
    target = fetch_catalog_sync(url, headers)
    print(f"服务器：{target.server_name} {target.server_version}  工具数：{len(target.tools)}")
    print(f"推断方式：{'规则 + 大模型' if use_llm else '仅规则'}\n")

    inferencer = SinkInferencer(use_llm=use_llm, cache_dir=OUT / ".sink_cache")
    results = inferencer.infer(target)

    hot = [r for r in results if r.sinks]
    for r in hot:
        tags = ", ".join(f"{s.type}({s.confidence}/{s.source})" for s in r.sinks)
        print(f"● {r.tool}.{r.param_path}  [{r.param_type}]")
        print(f"    → {tags}")
        for s in r.sinks:
            if s.reason:
                print(f"      · {s.reason}")

    total_params = len(results)
    print(f"\n有 sink 候选的参数：{len(hot)} / {total_params}")

    OUT.mkdir(exist_ok=True)
    safe = re.sub(r"[^\w.-]", "_", (target.server_name or "server"))
    path = OUT / f"{safe}_sinks.json"
    path.write_text(json.dumps(
        [{"tool": r.tool, "param_path": r.param_path, "param_type": r.param_type,
          "sinks": [vars(s) for s in r.sinks]} for r in results],
        ensure_ascii=False, indent=2))
    print(f"已保存：{path}")


if __name__ == "__main__":
    main()
