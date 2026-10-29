"""从三大漏洞库中筛出 MCP 相关漏洞，按编号别名合并去重。

输入：data/raw/ 下由 download.py 下载的 cvelist.zip、ghsa.zip、osv_npm.zip、osv_pypi.zip
输出：
  data/candidates.jsonl  每行一条合并后的漏洞
  data/candidates.csv    同上，便于用表格软件浏览

匹配规则偏宽松（目标是发现方向而非精确统计）：
  strong：出现 "Model Context Protocol"、FastMCP、mcp-server、xxx-mcp、mcp-xxx 等明确写法
  weak：只出现独立的大写 "MCP" 且上下文含 AI/LLM/agent/tool 等词，需人工复核
"""
import csv
import json
import re
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
OUT = ROOT / "data"
MCP_RELEASE = "2024-11-01"

STRONG = re.compile(
    r"model[\s-]*context[\s-]*protocol|fastmcp|@modelcontextprotocol"
    r"|\bmcp[-_ ]?servers?\b|\bmcp[-_][a-z0-9]|[a-z0-9][-_.]mcp\b",
    re.I,
)
WEAK = re.compile(r"\bMCP\b")
AI_CONTEXT = re.compile(r"\b(LLM|AI|agent|agentic|tool|Claude|Cursor|prompt)s?\b", re.I)


def match(text):
    if STRONG.search(text):
        return "strong"
    if WEAK.search(text) and AI_CONTEXT.search(text):
        return "weak"
    return None


def iter_zip_json(path, member_filter=lambda n: n.endswith(".json")):
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            if member_filter(name):
                try:
                    yield json.loads(z.read(name))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue


# ---------- OSV 格式（GHSA 仓库与 OSV.dev 共用） ----------

def from_osv(rec, source):
    pkgs = [a["package"]["name"] for a in rec.get("affected", []) if "package" in a]
    urls = [r["url"] for r in rec.get("references", [])]
    text = " ".join([rec.get("summary", ""), rec.get("details", ""), *pkgs, *urls])
    strength = match(text)
    if not strength:
        return None
    db = rec.get("database_specific", {})
    return {
        "ids": {rec["id"], *rec.get("aliases", [])},
        "summary": rec.get("summary", ""),
        "description": rec.get("details", ""),
        "packages": set(pkgs),
        "ecosystems": {a["package"].get("ecosystem", "") for a in rec.get("affected", []) if "package" in a},
        "cwes": set(db.get("cwe_ids") or []),
        "severity": db.get("severity", ""),
        "cvss": "",
        "published": rec.get("published", "")[:10],
        "reviewed": db.get("github_reviewed"),
        "urls": urls,
        "sources": {source},
        "match": strength,
    }


# ---------- CVE JSON 5 格式 ----------

def from_cve(rec):
    meta = rec.get("cveMetadata", {})
    if meta.get("state") != "PUBLISHED":
        return None
    containers = rec.get("containers", {})
    cna = containers.get("cna", {})
    desc = " ".join(d.get("value", "") for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en"))
    affected = cna.get("affected", [])
    names = [x for a in affected for x in (a.get("product"), a.get("packageName"), a.get("repo")) if x]
    urls = [r["url"] for r in cna.get("references", [])]
    text = " ".join([cna.get("title", ""), desc, *names, *urls])
    strength = match(text)
    if not strength:
        return None

    cwes, cvss, severity = set(), "", ""
    for c in [cna, *containers.get("adp", [])]:
        for pt in c.get("problemTypes", []):
            for d in pt.get("descriptions", []):
                if d.get("cweId"):
                    cwes.add(d["cweId"])
        for m in c.get("metrics", []):
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                if key in m and not cvss:
                    cvss = str(m[key].get("baseScore", ""))
                    severity = m[key].get("baseSeverity", "")
    return {
        "ids": {meta["cveId"]},
        "summary": cna.get("title", ""),
        "description": desc,
        "packages": set(names),
        "ecosystems": set(),
        "cwes": cwes,
        "severity": severity,
        "cvss": cvss,
        "published": meta.get("datePublished", "")[:10],
        "reviewed": None,
        "urls": urls,
        "sources": {"cvelist"},
        "match": strength,
    }


def iter_cvelist(path):
    """cvelistV5 的全量包是 zip 套 zip：外层只包含一个 cves.zip。"""
    with zipfile.ZipFile(path) as outer:
        inner_names = [n for n in outer.namelist() if n.endswith(".zip")]
    if inner_names:
        inner = RAW / "cvelist_inner.zip"
        if not inner.exists():
            print("  解压内层 cves.zip ...")
            with zipfile.ZipFile(path) as outer, open(inner, "wb") as f:
                f.write(outer.read(inner_names[0]))
        path = inner
    yield from iter_zip_json(path, lambda n: n.endswith(".json") and "/CVE-" in n)


# ---------- 合并 ----------

def merge(records):
    """按 ids（含别名）做并查集合并。"""
    merged = []
    index = {}
    for r in records:
        hits = {index[i] for i in r["ids"] if i in index}
        if not hits:
            merged.append(r)
            target = len(merged) - 1
        else:
            target = min(hits)
            base = merged[target]
            for other in sorted(hits - {target}, reverse=True):
                absorb(base, merged[other])
                merged[other] = None
            absorb(base, r)
        for i in merged[target]["ids"]:
            index[i] = target
    return [m for m in merged if m]


def absorb(base, r):
    for k in ("ids", "packages", "ecosystems", "cwes", "sources"):
        base[k] |= r[k]
    base["urls"] = list(dict.fromkeys(base["urls"] + r["urls"]))
    if r["match"] == "strong":
        base["match"] = "strong"
    # GHSA 的标题/描述通常更规整，优先保留
    if not base["summary"] or ("ghsa" in r["sources"] and r["summary"]):
        base["summary"] = r["summary"] or base["summary"]
    if len(r["description"]) > len(base["description"]):
        base["description"] = r["description"]
    base["cvss"] = base["cvss"] or r["cvss"]
    base["severity"] = base["severity"] or r["severity"]
    if r["reviewed"] is not None:
        base["reviewed"] = base["reviewed"] or r["reviewed"]
    dates = [d for d in (base["published"], r["published"]) if d]
    base["published"] = min(dates) if dates else ""


def finalize(r):
    ids = sorted(r["ids"])
    return {
        "key": next((i for i in ids if i.startswith("CVE-")), ids[0]),
        "cve": [i for i in ids if i.startswith("CVE-")],
        "ghsa": [i for i in ids if i.startswith("GHSA-")],
        "other_ids": [i for i in ids if not i.startswith(("CVE-", "GHSA-"))],
        "malicious_pkg": any(i.startswith("MAL-") for i in ids),
        "match": r["match"],
        "published": r["published"],
        "severity": r["severity"].upper(),
        "cvss": r["cvss"],
        "cwes": sorted(r["cwes"]),
        "packages": sorted(r["packages"]),
        "ecosystems": sorted(e for e in r["ecosystems"] if e),
        "github_reviewed": r["reviewed"],
        "sources": sorted(r["sources"]),
        "summary": r["summary"].strip(),
        "description": r["description"].strip(),
        "urls": r["urls"][:10],
    }


def main():
    records = []
    for name, source in (("osv_npm.zip", "osv"), ("osv_pypi.zip", "osv"), ("ghsa.zip", "ghsa")):
        print(f"扫描 {name} ...")
        before = len(records)
        records += [x for rec in iter_zip_json(RAW / name) if (x := from_osv(rec, source))]
        print(f"  命中 {len(records) - before}")
    print("扫描 cvelist.zip ...")
    before = len(records)
    records += [x for rec in iter_cvelist(RAW / "cvelist.zip") if (x := from_cve(rec))]
    print(f"  命中 {len(records) - before}")

    # MCP 于 2024-11-25 发布，此前的命中均为同名缩写（Unisys MCP 固件、mcp251x 芯片驱动等）
    rows = sorted(
        (r for r in map(finalize, merge(records)) if r["published"] >= MCP_RELEASE),
        key=lambda x: x["published"],
        reverse=True,
    )

    with open(OUT / "candidates.jsonl", "w") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    with open(OUT / "candidates.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        for row in rows:
            w.writerow({k: "; ".join(v) if isinstance(v, list) else v for k, v in row.items()})

    print(f"\n合并后共 {len(rows)} 条")
    print("匹配强度:", dict(Counter(r["match"] for r in rows)))
    print("恶意包(MAL-):", sum(r["malicious_pkg"] for r in rows))
    print("有 CVE 编号:", sum(bool(r["cve"]) for r in rows), " 仅 GHSA:", sum(bool(r["ghsa"]) and not r["cve"] for r in rows))
    print("按年:", dict(sorted(Counter(r["published"][:4] for r in rows).items())))
    print("Top CWE:", Counter(c for r in rows for c in r["cwes"]).most_common(15))


if __name__ == "__main__":
    main()
