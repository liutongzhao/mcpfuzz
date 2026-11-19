"""Keyword classifier (the non-LLM arm of stage 1, selected when --no-llm-sink).

Classifies a parameter purely by matching its NAME against a per-operation keyword lexicon that was
induced from CVEs (see dataset/keyword_lexicon.py; file: keyword_lexicon.json). Deterministic, no
weights: a parameter is classified into an operation iff its name matches a word in that operation's list.

Name only (not the description): the lexicon contains generic words that would match almost every
description, inflating keyword recall; matching the parameter name keeps the baseline meaningful.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from .types import OPERATIONS

_LEXICON_FILE = Path(__file__).resolve().parent / "keyword_lexicon.json"


@lru_cache(maxsize=1)
def _lexicon() -> dict[str, set]:
    """Load {operation: set(words)} from the induced lexicon. Empty sets if the file is missing."""
    out = {op: set() for op in OPERATIONS}
    try:
        data = json.loads(_LEXICON_FILE.read_text())
    except Exception:
        return out
    for op, spec in data.get("classes", {}).items():
        if op in out:
            out[op] = {e["word"].lower() for e in spec.get("words", [])}
    return out


def _leaf(path: str) -> str:
    """Last segment of a (possibly nested) parameter path: files[].path -> path, config.timeout -> timeout."""
    seg = re.split(r"[.\[]", path or "")[-1]
    return seg.strip("]")


def _candidates(name: str) -> set[str]:
    """Match forms for a parameter name: the whole name, a separator-normalized form, and word tokens."""
    low = name.lower()
    # split camelCase, then unify separators to underscore
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    norm = re.sub(r"[\-./ ]+", "_", spaced).lower().strip("_")
    cands = {low, norm}
    cands.update(t for t in norm.split("_") if t)
    return {c for c in cands if c}


def keyword_operations(param) -> tuple[set[str], dict[str, list]]:
    """Return (operations, provenance) for this parameter by name-matching the lexicon.
    provenance maps each hit operation to the list of matched keywords."""
    lex = _lexicon()
    cands = _candidates(_leaf(param.path or ""))
    ops: set[str] = set()
    prov: dict[str, list] = {}
    for op, words in lex.items():
        hit = sorted(cands & words)
        if hit:
            ops.add(op)
            prov[op] = [f"name matched keyword '{w}'" for w in hit]
    return ops, prov
