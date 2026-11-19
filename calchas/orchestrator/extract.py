"""Runtime value extraction: pull the value a from_step needs out of the producer's real response.

Three tiers, cheapest-and-most-deterministic first (see docs/from_step链改造设计.md):
1. recorded JSON path  — when the recipe captured where the value sat in the producer response, read that
   exact path from the fresh response (deterministic, no LLM, no guessing).
2. scored field match   — no path (planner-built recipe / schema drift): token-level key scoring over the JSON,
   pick the best-scoring leaf (not the first loose substring match).
3. fallbacks            — recorded value (agent path: deterministic, never touches the LLM at replay) or, when
   no value was recorded (planner path), the constrained LLM.

Also exposes find_value_path(), used at recipe-build time to record where a value sat, which both sharpens the
literal/from_step classification and feeds tier 1 here.
"""
from __future__ import annotations

import json
import re

from calchas.llmclient import complete

SYSTEM_EXTRACT = ("You extract one value from an MCP tool response. "
                  "Given the response and a description of what to extract, return ONLY the raw value "
                  "(no quotes, no explanation). If it is not present, return exactly NULL.")

# Noise words that show up in the (agent-built) extract description but are not field-name hints.
_STOP = {"value", "values", "looks", "look", "like", "the", "for", "from", "that", "this",
         "response", "step", "field", "real", "actual", "an", "of", "to", "or", "and", "a"}


def _split_tokens(s) -> list:
    """Split an identifier into lowercased tokens on camelCase and non-alnum boundaries (repo_id/repoId -> [repo,id])."""
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", str(s))
    return [p.lower() for p in re.split(r"[^A-Za-z0-9]+", s) if len(p) >= 2]


def _desc_keywords(desc) -> list:
    return [t for t in _split_tokens(desc) if t not in _STOP]


def _tok_hit(tok, kws) -> bool:
    """A token matches a keyword if equal, or (both >=3 chars) one is a prefix of the other (repo ~ repos)."""
    for k in kws:
        if tok == k:
            return True
        if len(tok) >= 3 and len(k) >= 3 and (tok.startswith(k) or k.startswith(tok)):
            return True
    return False


def _walk_paths(obj, prefix=()):
    """Yield (path_tuple, leaf_value) for every leaf; path elements are dict keys and list indices."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_paths(v, prefix + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_paths(v, prefix + (i,))
    else:
        yield prefix, obj


def find_value_path(response_text: str, value):
    """Return the JSON path (list of keys/indices) to the first leaf equal to `value`, or None.

    Used at recipe-build time: a value that EQUALS a structured leaf is strong evidence it came from that
    response (a real dependency); a value that merely appears as a substring of the serialized text is not
    (removes the 'action="current"' false from_step). Type-aware (native == or string ==)."""
    if not response_text:
        return None
    try:
        data = json.loads(response_text)
    except Exception:
        return None
    sval = str(value)
    for path, v in _walk_paths(data):
        if isinstance(v, bool):
            continue
        if v == value or str(v) == sval:
            return list(path)
    return None


def _read_path(response_text: str, path):
    """Read a recorded JSON path out of a fresh response; None if the path does not resolve to a non-empty scalar."""
    try:
        data = json.loads(response_text)
    except Exception:
        return None
    cur = data
    for key in path:
        if isinstance(cur, dict):
            if key in cur:
                cur = cur[key]
            elif str(key) in cur:
                cur = cur[str(key)]
            else:
                return None
        elif isinstance(cur, list):
            try:
                cur = cur[int(key)]
            except (ValueError, TypeError, IndexError):
                return None
        else:
            return None
    if cur in (None, "", []) or isinstance(cur, (dict, list)):
        return None
    return cur


def _field_match(text, extract_desc):
    """Scored key match over the JSON: token-level (not raw substring), pick the best-scoring leaf.

    Score = (fraction of key tokens that hit a keyword) + (1 if every key token hits) + 0.3*(path tokens that
    hit a keyword). Token-level matching kills 'id' matching inside 'width'; the path bonus breaks ties like
    owner.id vs repos.id when the keyword is 'repo_id'. Returns the best value or None."""
    try:
        data = json.loads(text)
    except Exception:
        return None
    kws = _desc_keywords(extract_desc)
    if not kws:
        return None
    best, best_score = None, 0.0
    for path, v in _walk_paths(data):
        if v in (None, "", []) or isinstance(v, bool) or not path:
            continue
        kt = _split_tokens(path[-1])
        if not kt:
            continue
        keyhits = sum(1 for t in kt if _tok_hit(t, kws))
        if keyhits == 0:
            continue                                   # no token-level key match -> not a candidate
        path_toks = [t for p in path[:-1] for t in _split_tokens(p)]
        score = (keyhits / len(kt)) + (1.0 if keyhits == len(kt) else 0.0) \
            + 0.3 * sum(1 for t in path_toks if _tok_hit(t, kws))
        if score > best_score:
            best_score, best = score, v
    return best


def _llm_extract(text, extract_desc):
    user = f"Extract: {extract_desc}\n\nResponse:\n{text[:3000]}"
    try:
        val = complete(SYSTEM_EXTRACT, user, max_tokens=200).strip()
    except Exception:
        return None
    return None if val in ("", "NULL", "null") else val


def extract_value(response_text: str, extract_desc: str = "", path=None, value=None):
    """Return the extracted value (native type preferred), or None.

    Order: recorded path -> scored field match -> recorded value (agent path, deterministic, no LLM) -> LLM
    (planner path only, when no value was recorded). The recorded-value fallback is what stops a single
    unresolvable from_step from SKIPping the whole tool."""
    if path:
        v = _read_path(response_text, path)
        if v is not None:
            return v
    if response_text:
        v = _field_match(response_text, extract_desc)
        if v is not None:
            return v
    if value is not None:
        return value                                   # deterministic fallback to the value discovery used
    if not response_text:
        return None
    return _llm_extract(response_text, extract_desc)
