"""Runtime value extraction: pull the value a from_step needs out of the producer's real response.

First try field-name / JSON-path matching; if that fails or the text is free-form, fall back to the LLM.
"""
from __future__ import annotations

import json
import re

from calchas.llmclient import complete

SYSTEM_EXTRACT = ("You extract one value from an MCP tool response. "
                  "Given the response and a description of what to extract, return ONLY the raw value "
                  "(no quotes, no explanation). If it is not present, return exactly NULL.")

# Take likely field keywords from the extract description (English words and camelCase fragments)
_WORD = re.compile(r"[A-Za-z][A-Za-z0-9_]{1,}")


def _walk(obj):
    """Walk the JSON, yielding (key, value) leaf pairs."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                yield from _walk(v)
            else:
                yield str(k), v
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v)


def _field_match(text, extract_desc):
    try:
        data = json.loads(text)
    except Exception:
        return None
    keys = [w.lower() for w in _WORD.findall(extract_desc)]
    if not keys:
        return None
    for k, v in _walk(data):
        kl = k.lower()
        if any(key == kl or key in kl or kl in key for key in keys) and v not in (None, "", []):
            return v
    return None


def _llm_extract(text, extract_desc):
    user = f"Extract: {extract_desc}\n\nResponse:\n{text[:3000]}"
    try:
        val = complete(SYSTEM_EXTRACT, user, max_tokens=200).strip()
    except Exception:
        return None
    return None if val in ("", "NULL", "null") else val


def extract_value(response_text: str, extract_desc: str):
    """Return the extracted value (native type preferred), or None."""
    if not response_text:
        return None
    v = _field_match(response_text, extract_desc)
    if v is not None:
        return v
    return _llm_extract(response_text, extract_desc)
