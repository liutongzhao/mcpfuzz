"""检测入口：连接目标 → 列清单 → 推 sink → 编排攻击序列 → 判定 → 报告。

用法：
  python run_detect.py <URL | config.json> [名称] [--tool 工具名] [--no-llm-sink]
  --tool 可多次，限定只测某些工具（调试用）；--no-llm-sink 让 sink 推断只用规则。
结果保存到 out/<server>_findings.json。
"""
import json
import re
import sys
from pathlib import Path

from mcpfuzz.driver import fetch_catalog_sync
from mcpfuzz.oracle import Oracle
from mcpfuzz.orchestrator import CONFIRMED, LIKELY_CLEAN, UNREACHED, Orchestrator
from mcpfuzz.sink import SinkInferencer
from mcpfuzz.targetcfg import resolve_target

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
        sys.exit("用法: python run_detect.py <URL | config.json> [名称] [--tool 名] [--no-llm-sink]")

    url, headers = resolve_target(argv[0], argv[1] if len(argv) > 1 else None)
    print(f"连接 {url} …" + ("（带鉴权头）" if headers else ""))
    catalog = fetch_catalog_sync(url, headers)
    print(f"服务器：{catalog.server_name} {catalog.server_version}  工具数：{len(catalog.tools)}")

    print("推断 sink …")
    param_sinks = SinkInferencer(use_llm=use_llm_sink, cache_dir=OUT / ".sink_cache").infer(catalog)

    oracle = Oracle()
    orch = Orchestrator(url, headers, catalog, oracle, cache_dir=OUT)
    print("开始检测" + (f"（仅 {sorted(only)}）" if only else "") + " …")
    findings = orch.run(param_sinks, only_tools=only or None)

    confirmed = [f for f in findings if f.status == CONFIRMED]
    print("\n================ 检测结果 ================")
    print(f"确认漏洞 {len(confirmed)} | 疑似无漏洞 {sum(f.status==LIKELY_CLEAN for f in findings)} "
          f"| 未触达 {sum(f.status==UNREACHED for f in findings)} | 总计 {len(findings)}")
    for f in confirmed:
        print(f"\n● [确认] {f.tool}.{f.param}  ({f.sink}, 通道 {f.channel})")
        print(f"    载荷: {f.payload!r}")
        print(f"    证据: {f.evidence}")

    OUT.mkdir(exist_ok=True)
    safe = re.sub(r"[^\w.-]", "_", (catalog.server_name or "server"))
    path = OUT / f"{safe}_findings.json"
    path.write_text(json.dumps([vars(f) for f in findings], ensure_ascii=False, indent=2))
    print(f"\n已保存：{path}")


if __name__ == "__main__":
    main()
