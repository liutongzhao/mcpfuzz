"""对 classify.py 的标注结果做交叉统计，输出到 data/analysis/。

目标子集（与论文范围一致）：
  组件为 MCP 服务器或网关，攻击面在服务端，且从 MCP 协议入口触发（tools/call、resources、prompts、HTTP 传输层）

用法：python3 scripts/analyze.py
"""
import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
OUT = DATA / "analysis"

TARGET_COMPONENTS = {"mcp_server", "mcp_gateway"}
MCP_INTERFACES = {"tools_call", "resources_read", "prompts_get", "transport_http"}


def load():
    return [json.loads(l) for l in open(DATA / "classified.jsonl")]


def L(r, field):
    return r[f"label_{field}"]


def is_target(r):
    return (L(r, "component") in TARGET_COMPONENTS and L(r, "attack_target") == "server_side"
            and L(r, "trigger_interface") in MCP_INTERFACES)


def pct(n, total):
    return f"{n} ({n / total:.0%})" if total else "0"


def crosstab(rows, row_field, col_field, out):
    cols = [c for c, _ in Counter(L(r, col_field) for r in rows).most_common()]
    table = defaultdict(Counter)
    for r in rows:
        table[L(r, row_field)][L(r, col_field)] += 1
    out.append(f"{row_field} × {col_field}")
    out.append(f"{'':30s}" + "".join(f"{c[:14]:>15s}" for c in cols) + f"{'合计':>8s}")
    for key, cnt in sorted(table.items(), key=lambda kv: -sum(kv[1].values())):
        out.append(f"{key:30s}" + "".join(f"{cnt[c]:>15d}" for c in cols) + f"{sum(cnt.values()):>8d}")
    out.append("")


def main():
    OUT.mkdir(exist_ok=True)
    rows = load()
    target = [r for r in rows if is_target(r)]
    out = []

    out.append(f"全部非恶意记录 {len(rows)} 条；目标子集（MCP 服务器/网关 + 服务端 + MCP 协议入口）{len(target)} 条\n")

    out.append("== 筛选漏斗 ==")
    s1 = [r for r in rows if L(r, "component") != "not_mcp"]
    s2 = [r for r in s1 if L(r, "component") in TARGET_COMPONENTS]
    s3 = [r for r in s2 if L(r, "attack_target") == "server_side"]
    for name, sub in (("去除误报", s1), ("仅 MCP 服务器/网关", s2), ("攻击面在服务端", s3), ("从 MCP 协议入口触发", target)):
        out.append(f"  {name:20s} {len(sub)}")
    out.append("")

    out.append("== 目标子集按月数量 ==")
    for month, n in sorted(Counter(r["published"][:7] for r in target).items()):
        out.append(f"  {month}  {n:4d}  " + "#" * (n // 3))
    out.append("")

    out.append("== 目标子集严重程度 ==")
    for k, n in Counter(r["severity"] or "无" for r in target).most_common():
        out.append(f"  {k:10s} {pct(n, len(target))}")
    out.append("")

    out.append("== 目标子集生态 ==")
    for k, n in Counter(e for r in target for e in (r["ecosystems"] or ["(仅CVE,无包信息)"])).most_common():
        out.append(f"  {k:20s} {n}")
    out.append("")

    out.append("== 目标子集：黑盒可检测性 ==")
    for k, n in Counter(L(r, "blackbox_detectable") for r in target).most_common():
        out.append(f"  {k:10s} {pct(n, len(target))}")
    out.append("")

    for a, b in (("vuln_class", "blackbox_detectable"), ("vuln_class", "needs_multi_step"),
                 ("vuln_class", "needs_multi_identity"), ("vuln_class", "oracle"),
                 ("vuln_class", "attacker_position"), ("vuln_class", "trigger_interface")):
        crosstab(target, a, b, out)

    detectable = [r for r in target if L(r, "blackbox_detectable") in ("yes", "partial")]
    out.append(f"== 可黑盒检测（yes+partial）{len(detectable)} 条中的状态需求 ==")
    ms = sum(L(r, "needs_multi_step") == "yes" for r in detectable)
    mi = sum(L(r, "needs_multi_identity") == "yes" for r in detectable)
    either = sum(L(r, "needs_multi_step") == "yes" or L(r, "needs_multi_identity") == "yes" for r in detectable)
    out.append(f"  需要多步调用   {pct(ms, len(detectable))}")
    out.append(f"  需要多身份     {pct(mi, len(detectable))}")
    out.append(f"  二者至少其一   {pct(either, len(detectable))}")
    out.append("")

    out.append("== 同一软件包多次出漏洞（目标子集，Top 20）==")
    pkg = Counter(p for r in target for p in r["packages"][:1])
    for p, n in pkg.most_common(20):
        out.append(f"  {n:3d}  {p}")
    repeat = sum(1 for n in pkg.values() if n > 1)
    out.append(f"  不同软件包 {len(pkg)} 个，其中出现 2 次及以上的 {repeat} 个")
    out.append("")

    out.append("== 其他组件的漏洞类型（了解范围外的部分）==")
    for comp in ("ai_platform", "sdk", "client_host", "dev_tool"):
        sub = [r for r in rows if L(r, "component") == comp]
        top = ", ".join(f"{k}:{n}" for k, n in Counter(L(r, "vuln_class") for r in sub).most_common(5))
        out.append(f"  {comp:12s} {len(sub):4d}  {top}")
    out.append("")

    out.append(f"== 置信度（目标子集）==  " + str(dict(Counter(L(r, "confidence") for r in target))))

    text = "\n".join(out)
    (OUT / "report.txt").write_text(text)
    with open(OUT / "target_subset.jsonl", "w") as f:
        for r in target:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(text)
    print(f"\n已写入 {OUT}/report.txt 与 target_subset.jsonl")


if __name__ == "__main__":
    main()
