#!/usr/bin/env python3
"""汇总各 cell 的扫描产物成一张表，并给生态测量的分母（部署成功率）。

用法：
  python3 collect.py results/                 # 收 results/ 下所有 cell
  python3 collect.py results/ --out merged     # 另存 merged.csv

口径：
  - 「部署失败」= 该目标在 batch_summary 里带 error（含「tools=0 后端未就绪」「连接失败」等；
    扫描器对起不来的后端会记成 error 而不是崩，见 calchas/run.py）。
  - 「部署成功」= 无 error，即起来且 tools>0、完整扫完。
  - 部署失败的目标会在整批跑完后补跑一轮（扫描器 --deploy-retry-rounds），attempts 列记第几次才定论。
  - 「有发现」= confirmed>0 或 suspected>0（人工复核前的工具判定）。
纯标准库。多机器：先把各机 results/ 汇到一处再跑本脚本。
"""
import argparse
import csv
import json
import re
import sys
from pathlib import Path


def load_json(p, default=None):
    try:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    except Exception:
        return default


def gwname_from_target(target):
    m = re.search(r"/mcp/([^/?#]+)", target or "")
    return m.group(1) if m else (target or "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", help="结果根目录（通常是 deploy/cells/results/）")
    ap.add_argument("--out", default="merged", help="输出前缀（默认 merged → merged.csv）")
    args = ap.parse_args()

    root = Path(args.root)
    summaries = sorted(root.glob("*/*/batch_summary.json"))
    if not summaries:
        sys.exit(f"在 {root} 下没找到任何 */*/batch_summary.json（cell 还没跑完？）")

    rows = []
    for sm in summaries:
        cell = sm.parent.parent.name          # results/<cell>/<slug>/batch_summary.json
        namemap = load_json(sm.parent.parent / "namemap.json", {}) or {}
        results = load_json(sm, []) or []
        for r in results:
            gw = gwname_from_target(r.get("target", ""))
            info = namemap.get(gw, {})
            err = r.get("error")
            tools_seen = ""
            rd = r.get("run_dir")
            if rd:
                cat = load_json(sm.parent / Path(rd).name / "catalog.json")
                if isinstance(cat, dict):
                    tools_seen = len(cat.get("tools") or [])
            rows.append({
                "cell": cell,
                "gateway_name": gw,
                "name": info.get("name", ""),
                "identifier": info.get("identifier", ""),
                "registryType": info.get("registryType", ""),
                "deployed": "no" if err else "yes",
                "attempts": r.get("attempt", 1),
                "tools_expected": info.get("tools_count_expected", ""),
                "tools_seen": tools_seen,
                "confirmed": r.get("confirmed", "") if not err else "",
                "suspected": r.get("suspected", "") if not err else "",
                "clean": r.get("clean", "") if not err else "",
                "unreached": r.get("unreached", "") if not err else "",
                "error": (err or "")[:200],
            })

    out_csv = Path(f"{args.out}.csv")
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    n = len(rows)
    dep = sum(r["deployed"] == "yes" for r in rows)
    conf = sum(1 for r in rows if r["deployed"] == "yes" and (r["confirmed"] or 0) and r["confirmed"] != "" and int(r["confirmed"]) > 0)
    susp = sum(1 for r in rows if r["deployed"] == "yes" and r["suspected"] != "" and int(r["suspected"] or 0) > 0)
    print(f"汇总 {len(summaries)} 个 cell，共 {n} 个目标：")
    late = sum(1 for r in rows if r["deployed"] == "yes" and int(r["attempts"]) > 1)
    print(f"  部署成功 {dep}（{dep*100//max(n,1)}%，其中补跑才成功 {late}） / 部署失败 {n-dep}")
    print(f"  含确认(confirmed>0) {conf} / 含疑似(suspected>0) {susp}")
    print(f"  明细 → {out_csv}")


if __name__ == "__main__":
    main()
