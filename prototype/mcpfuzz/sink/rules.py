"""规则层：按参数名/描述给出"抬升"候选（通用关键词启发式，不针对任何服务器）。

作用是大模型的**确定性召回下界**——即使大模型漏判，规则命中也会把对应类别从地板抬起来。
与大模型层取并集（max）。只对可注入（字符串类/数组含字符串）参数提候选。
"""
from __future__ import annotations

import re

from .types import AI, CI, CODE, PT, QI, SSRF, W_LOW, W_MED, Raise

# (关键词正则, 注入类别)。命中参数名 → 中证据(W_MED)；仅命中描述 → 弱证据(W_LOW)。
RULES = [
    (r"\b(path|file|dir|folder|filename|filepath|location|dest|destination|output|input)\b", PT),
    (r"\b(url|uri|urls|href|endpoint|host|hostname|webhook|callback|link|address|server|proxy|upstream|"
     r"target|source|src|site|page|domain|remote|feed|resource|origin|image|img|avatar|favicon|"
     r"icon|thumbnail|screenshot|fetch|download|request|scrape|crawl|preview)\b", SSRF),
    (r"\b(cmd|command|exec|shell|bash|script|run)\b", CI),
    (r"\b(ref|arg|args|argument|flag|flags|option|options)\b", AI),
    (r"\b(query|sql|filter|search|statement|where|cypher|kql|dql|graphql)\b", QI),
    (r"\b(code|expr|expression|eval|template|formula)\b", CODE),
]


def _normalize(s: str) -> str:
    """把 snake_case/kebab/点路径/camelCase 拆成空格分词，否则 \\b 词边界不在下划线处断开，
    像 image_url / file_path / targetUrl 这类复合名会一个关键词都命不中（通用召回漏洞）。"""
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", s)   # camelCase → 空格
    s = re.sub(r"[_\-./]+", " ", s)                  # 下划线/连字符/点/斜杠 → 空格
    return s.lower()


def rule_raises(param) -> list[Raise]:
    """返回该参数的规则抬升列表（每类最多一条，取最强）。"""
    name = _normalize(param.path or "")
    desc = _normalize(param.description or "")
    best: dict[str, Raise] = {}
    for pat, cls in RULES:
        if re.search(pat, name):
            best[cls] = Raise(cls, W_MED, "rule", f"参数名命中 {cls} 关键词")
        elif re.search(pat, desc) and cls not in best:
            best[cls] = Raise(cls, W_LOW, "rule", f"描述命中 {cls} 关键词")
    return list(best.values())
