"""运行时取值：从生产者的真实响应里抽出某个 from_step 需要的值。

先字段名/JSON 路径匹配，匹配不到或为自由文本再用大模型兜底。
"""
from __future__ import annotations

import json
import re

from mcpfuzz.llmclient import complete

SYSTEM_EXTRACT = ("You extract one value from an MCP tool response. "
                  "Given the response and a description of what to extract, return ONLY the raw value "
                  "(no quotes, no explanation). If it is not present, return exactly NULL.")

# 从 extract 描述里取可能的字段关键词（英文单词与 camelCase 片段）
_WORD = re.compile(r"[A-Za-z][A-Za-z0-9_]{1,}")


def _walk(obj):
    """遍历 JSON，产出 (key, value) 叶子对。"""
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
    """返回抽到的值（原生类型优先），或 None。"""
    if not response_text:
        return None
    v = _field_match(response_text, extract_desc)
    if v is not None:
        return v
    return _llm_extract(response_text, extract_desc)
