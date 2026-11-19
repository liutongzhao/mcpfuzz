"""从 CVE 官方库全量归纳四类危险操作的参数名词表，作为阶段一关键词匹配的词表。

思路参照 NAUTILUS（USENIX Security 2023）：从真实 CVE 归纳模式，而不是作者手写关键词。

四类（命令注入与参数注入在黑盒下分不开，合并为"外部程序"）：
  external_program  ← CWE-78 命令注入、CWE-88 参数注入
  file_path         ← CWE-22/23/36/73/98 路径穿越/文件包含
  network_address   ← CWE-918 SSRF
  code_eval         ← CWE-94/95/917/1336 代码注入/eval/表达式/模板注入（排除 XSS）

每个词有三种来源，全部机械收录，不做人工挑选：
  cve_core  在 >=4 条不同 CVE 描述里被抽为注入点名字
  cve_low   在 2~3 条不同 CVE 里出现
  gf        Gf-Patterns 社区词表原样收录（固定到某个 commit）

为避免"拿答案配词表"，归纳语料排除：
  - 评测集 data/groundtruth/round2/数据集总表.md 里出现的所有 CVE 编号；
  - 所有 MCP 相关 CVE（沿用 collect.py 的 STRONG 规则）。

输入：data/raw/cvelist_inner.zip（download.py 下载的 CVE 全量包）
外部来源缓存：data/raw/lexicon_src/（Gf-Patterns 文件、NLTK 英文停用词）
输出：calchas/sink/keyword_lexicon.json

用法：.venv/bin/python dataset/keyword_lexicon.py
"""
import hashlib
import io
import json
import re
import subprocess
import sys
import zipfile
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from collect import STRONG  # noqa: E402  MCP 相关判定，与数据集流水线保持一致

ROOT = Path(__file__).resolve().parent.parent
CVELIST = ROOT / "data" / "raw" / "cvelist_inner.zip"
EVAL_TABLE = ROOT / "data" / "groundtruth" / "round2" / "数据集总表.md"
SRC_CACHE = ROOT / "data" / "raw" / "lexicon_src"
OUT = ROOT / "calchas" / "sink" / "keyword_lexicon.json"

MIN_CVE = 2      # 至少出现在几条不同 CVE 里才收录
CORE_CVE = 4     # 达到这个数记为 cve_core，否则记为 cve_low

GF_REPO = "1ndianl33t/Gf-Patterns"
GF_COMMIT = "f686f06ae647726578920084c894100d702496cc"
NLTK_STOPWORDS_URL = "https://raw.githubusercontent.com/nltk/nltk_data/gh-pages/packages/corpora/stopwords.zip"

CLASSES = {
    "external_program": {"cwe": ["78", "88"], "maps_to": ["command_injection", "argument_injection"], "gf": "rce.json"},
    "file_path": {"cwe": ["22", "23", "36", "73", "98"], "maps_to": ["path_traversal"], "gf": "lfi.json"},
    "network_address": {"cwe": ["918"], "maps_to": ["ssrf"], "gf": "ssrf.json"},
    "code_eval": {"cwe": ["94", "95", "917", "1336"], "maps_to": ["code_injection"], "gf": "ssti.json"},
}
CWE2CLASS = {cwe: cls for cls, spec in CLASSES.items() for cwe in spec["cwe"]}
XSS = re.compile(r"cross[- ]site scripting|\bXSS\b", re.I)

# 从描述里抽"注入点名字"的固定句式
TOK = r"([A-Za-z_][A-Za-z0-9_\-]{1,40})"
PATTERNS = [re.compile(p, re.I) for p in [
    r"manipulation of the argument " + TOK,
    r"\bargument ['\"`]?" + TOK + r"['\"`]?(?: leads| parameter| of| in|,|\.)",
    r"\bthe ['\"`]" + TOK + r"['\"`] (?:parameter|argument|field|request parameter|GET|POST)",
    r"\bvia (?:the )?['\"`]?" + TOK + r"['\"`]? parameter",
    r"\b" + TOK + r" parameter\b",
    r"\bparameter[s]? ['\"`]?" + TOK,
    r"\bthe `" + TOK + r"`",
]]

# 解析停用词：句式模板本身的词 + CVE 描述里的套话。只用于剔除句式误抓，
# 刻意不包含任何可能是参数名的词（url/name/id/file/server/remote 等交给频率去筛）。
PARSE_STOP = set("""
the a an this that these those http https get post put following same argument parameter parameters
which affected unknown some crafted their is are was were of in to and or it its by as via leads lead
manipulation component components provided directly when then into belonging might before after with
without from can could may must also such other another any all each both more most less few many much
very so than within through over under above below between during against about across along among
around because been being had has have having not no nor only own too dangerous checks separation vector
attacker attackers vulnerability vulnerabilities allows allow affects unauthenticated authenticated
arbitrary malicious specially sensitive prior using used use contains contain discovered reported known
classified found processing specific certain multiple single leading due where what how who whom whose
will would should shall does did do done able unable likely possible cause causes caused result results
resulting improper proper neutralization special elements element injection execution executing
""".split())


def fetch(url, dest):
    if not dest.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["curl", "-sSfL", "--retry", "3", "-o", str(dest), url], check=True)
    return dest.read_bytes()


def load_nltk_stopwords():
    raw = fetch(NLTK_STOPWORDS_URL, SRC_CACHE / "nltk_stopwords.zip")
    text = zipfile.ZipFile(io.BytesIO(raw)).read("stopwords/english").decode()
    return set(text.split()), hashlib.sha256(text.encode()).hexdigest()


def load_gf(fname):
    url = f"https://raw.githubusercontent.com/{GF_REPO}/{GF_COMMIT}/{fname}"
    data = json.loads(fetch(url, SRC_CACHE / f"gf_{GF_COMMIT[:12]}_{fname}"))
    words = set()
    for p in data.get("patterns", []):
        w = p.strip().rstrip("=").lower()
        if re.fullmatch(r"[a-z][a-z0-9_\-]*", w):
            words.add(w)
    return words


def load_eval_cves():
    return set(re.findall(r"CVE-\d{4}-\d+", EVAL_TABLE.read_text()))


def clean(token):
    return token.strip().strip("`'\".,;:()[]{}").lower().rstrip(".")


def extract(desc, stop):
    out = set()
    for pat in PATTERNS:
        for m in pat.findall(desc):
            t = clean(m)
            if len(t) < 2 or t in stop or t.isdigit():
                continue
            if re.fullmatch(r"[a-z][a-z0-9_\-]{1,40}", t):
                out.add(t)
    return out


def main():
    nltk_stop, nltk_sha = load_nltk_stopwords()
    stop = PARSE_STOP | nltk_stop
    eval_cves = load_eval_cves()

    counts = defaultdict(Counter)
    stats = defaultdict(lambda: Counter())
    excluded = Counter()
    zf = zipfile.ZipFile(CVELIST)
    names = [n for n in zf.namelist() if n.endswith(".json") and "/CVE-" in n]
    for i, name in enumerate(names):
        if i % 100000 == 0:
            print(f"... {i}/{len(names)}", file=sys.stderr, flush=True)
        try:
            rec = json.loads(zf.read(name))
        except Exception:
            continue
        if not isinstance(rec, dict):
            continue
        cna = rec.get("containers", {}).get("cna", {})
        if not isinstance(cna, dict):
            continue
        cwes = set(re.findall(r"CWE-(\d+)", json.dumps(cna.get("problemTypes", []))))
        classes = {CWE2CLASS[c] for c in cwes if c in CWE2CLASS}
        if not classes:
            continue
        desc = next((d.get("value", "") for d in cna.get("descriptions", [])
                     if isinstance(d, dict) and d.get("lang", "").startswith("en")), "")
        if not desc:
            continue
        cve_id = Path(name).stem
        if cve_id in eval_cves:
            excluded["eval_set"] += 1
            continue
        if STRONG.search(desc) or STRONG.search(json.dumps(cna.get("affected", []))):
            excluded["mcp_related"] += 1
            continue
        if "code_eval" in classes and ("79" in cwes or XSS.search(desc)):
            classes.discard("code_eval")
            excluded["code_eval_xss"] += 1
            if not classes:
                continue
        tokens = extract(desc, stop)
        for cls in classes:
            stats[cls]["cves"] += 1
            if tokens:
                stats[cls]["cves_with_name"] += 1
            for t in tokens:
                counts[cls][t] += 1

    lexicon = {}
    for cls, spec in CLASSES.items():
        gf_words = load_gf(spec["gf"])
        entries = {}
        for w, n in counts[cls].items():
            if n >= MIN_CVE:
                entries[w] = {"word": w, "cve_count": n,
                              "sources": ["cve_core" if n >= CORE_CVE else "cve_low"]}
        for w in gf_words:
            e = entries.setdefault(w, {"word": w, "cve_count": counts[cls].get(w, 0), "sources": []})
            e["sources"].append("gf")
        words = sorted(entries.values(), key=lambda e: (-e["cve_count"], e["word"]))
        lexicon[cls] = {
            "cwe": [f"CWE-{c}" for c in spec["cwe"]],
            "maps_to": spec["maps_to"],
            "gf_file": spec["gf"],
            "cves": stats[cls]["cves"],
            "cves_with_name": stats[cls]["cves_with_name"],
            "words": words,
        }

    meta = {
        "generated": date.today().isoformat(),
        "generator": "dataset/keyword_lexicon.py",
        "method": "CWE 归类 + 固定句式从 CVE 描述抽注入点名字 + 跨 CVE 频率筛选 + Gf-Patterns 原样合并",
        "cvelist_sha256": hashlib.sha256(CVELIST.read_bytes()).hexdigest(),
        "min_cve": MIN_CVE,
        "core_cve": CORE_CVE,
        "gf": {"repo": GF_REPO, "commit": GF_COMMIT},
        "nltk_stopwords_english_sha256": nltk_sha,
        "excluded": dict(excluded),
        "eval_cves_excluded_list_size": len(eval_cves),
    }
    OUT.write_text(json.dumps({"meta": meta, "classes": lexicon}, ensure_ascii=False, indent=1) + "\n")

    print(f"\n已写入 {OUT.relative_to(ROOT)}")
    print("排除:", dict(excluded))
    for cls, v in lexicon.items():
        src = Counter(s for e in v["words"] for s in e["sources"])
        print(f"{cls:<17} CVE {v['cves']:>5}  抽到名字 {v['cves_with_name']:>5}  词 {len(v['words']):>4}  来源 {dict(src)}")


if __name__ == "__main__":
    main()
