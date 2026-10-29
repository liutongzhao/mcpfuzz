"""规则层：按参数名/描述/类型给出候选 sink（通用关键词启发式，不针对任何服务器）。"""
from __future__ import annotations

import re

from .types import AI, CI, CODE, PT, QI, SSRF, SinkLabel

# (关键词正则, sink 类型)。顺序不影响，命中即加候选。
RULES = [
    (r"\b(path|file|dir|folder|filename|filepath|location|dest|destination|output|input)\b", PT),
    (r"\b(url|uri|href|endpoint|host|hostname|webhook|callback|link|address|server|proxy|upstream)\b", SSRF),
    (r"\b(cmd|command|exec|shell|bash|script|run)\b", CI),
    (r"\b(ref|arg|args|argument|flag|flags|option|options)\b", AI),
    (r"\b(query|sql|filter|search|statement|where|cypher|kql|dql|graphql)\b", QI),
    (r"\b(code|expr|expression|eval|template|formula)\b", CODE),
]
STRINGY = {"string", "union", "unknown"}


def rule_sinks(param) -> list[SinkLabel]:
    # 只对字符串类参数提注入候选；数值/布尔/受 enum 约束的交给大模型，规则不乱提
    if param.type not in STRINGY:
        return []
    name = param.path.lower()
    desc = (param.description or "").lower()
    best: dict[str, SinkLabel] = {}
    for pat, sink in RULES:
        if re.search(pat, name):
            best[sink] = SinkLabel(sink, "high", "rule", f"参数名命中 {sink} 关键词")
        elif re.search(pat, desc) and sink not in best:
            best[sink] = SinkLabel(sink, "low", "rule", f"描述命中 {sink} 关键词")
    return list(best.values())
