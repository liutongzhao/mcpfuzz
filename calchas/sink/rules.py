"""Rule layer: propose "raise" candidates from parameter name/description (generic keyword
heuristics, not targeted at any specific server).

Its role is a deterministic recall floor under the LLM — even if the LLM misses a label, a rule
hit will lift the corresponding class up off the floor. Combined with the LLM layer by union (max).
Only proposes candidates for injectable (string-like / array-of-string) parameters.
"""
from __future__ import annotations

import re

from .types import AI, CI, CODE, PT, QI, SSRF, W_LOW, W_MED, Raise

# (keyword regex, injection class). Hit on the parameter name -> medium evidence (W_MED);
# hit on the description only -> weak evidence (W_LOW).
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
    """Split snake_case/kebab/dotted-path/camelCase into space-separated words; otherwise the \\b word
    boundary does not break at underscores, so compound names like image_url / file_path / targetUrl would
    match no keyword at all (a general recall hole)."""
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", s)   # camelCase -> space
    s = re.sub(r"[_\-./]+", " ", s)                  # underscore / hyphen / dot / slash -> space
    return s.lower()


def rule_raises(param) -> list[Raise]:
    """Return the rule-raise list for this parameter (at most one per class, keeping the strongest)."""
    name = _normalize(param.path or "")
    desc = _normalize(param.description or "")
    best: dict[str, Raise] = {}
    for pat, cls in RULES:
        if re.search(pat, name):
            best[cls] = Raise(cls, W_MED, "rule", f"parameter name matched {cls} keyword")
        elif re.search(pat, desc) and cls not in best:
            best[cls] = Raise(cls, W_LOW, "rule", f"description matched {cls} keyword")
    return list(best.values())
