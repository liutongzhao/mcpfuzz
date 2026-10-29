"""大模型层：按工具批量推断每个参数的 sink。复用中转，带本地缓存。"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

from mcpfuzz.llm_config import API_KEY, BASE_URL, MODEL

from .types import SINK_TYPES

SYSTEM = """You label MCP tool parameters for black-box server-side injection testing.
For each parameter, decide which dangerous operation(s) its value likely flows into (the "sink"). Use ONLY these sink types:
- command_injection: value reaches an OS shell / command execution
- argument_injection: value becomes a command-line argument/flag of an invoked program
- path_traversal: value is used as a filesystem path
- ssrf: value becomes a URL/host the server will request
- query_injection: value is interpolated into a database/query language (SQL/NoSQL/Cypher/KQL/GraphQL)
- code_injection: value is evaluated as code or a template (eval/exec/Jinja/etc.)

A parameter may map to several sinks, or to none.
IMPORTANT: judge by what the TOOL does (from its name and description), not just the parameter name. An innocuous-looking parameter can be a sink if the tool performs system/file/network/database operations with it. Parameters that are booleans, fixed enums, or purely numeric identifiers are usually none.

For each parameter give confidence "high" or "low" and a one-sentence reason in Chinese.
Return ONLY a JSON object mapping each parameter path to a list:
{ "<param_path>": [ {"type": "...", "confidence": "high|low", "reason": "..."} ], ... }
A parameter with no sink maps to []. Output nothing but the JSON."""


def _call(messages, timeout=120) -> str:
    payload = json.dumps({"model": MODEL, "messages": messages, "max_tokens": 1800})
    # 用 curl：该中转在部分环境下 python urllib 的 SSL 会失败；且不传 temperature（会 502）
    p = subprocess.run(
        ["curl", "-sS", "-m", str(timeout), BASE_URL,
         "-H", f"Authorization: Bearer {API_KEY}", "-H", "Content-Type: application/json",
         "-d", "@-", "-w", "\n%{http_code}"],
        input=payload, capture_output=True, text=True,
    )
    if p.returncode != 0:
        raise RuntimeError(f"curl 失败({p.returncode}): {p.stderr.strip()[:200]}")
    body, _, code = p.stdout.rpartition("\n")
    if code != "200":
        raise RuntimeError(f"HTTP {code}: {body[:200]}")
    return json.loads(body)["choices"][0]["message"]["content"]


def _parse(text) -> dict:
    text = re.sub(r"```(?:json)?", "", text).strip()
    s, e = text.find("{"), text.rfind("}")
    if s == -1 or e <= s:
        raise ValueError("回复无 JSON 对象")
    return json.loads(text[s:e + 1])


def _tool_key(tool) -> str:
    sig = [tool.name, tool.description,
           [(p.path, p.type, p.description, p.enum, p.required) for p in tool.params]]
    return hashlib.sha256(json.dumps(sig, ensure_ascii=False).encode()).hexdigest()[:16]


def _user_content(tool) -> str:
    lines = [f"tool: {tool.name}", f"description: {(tool.description or '')[:600]}", "parameters:"]
    for p in tool.params:
        enum = f" enum={p.enum[:6]}" if p.enum else ""
        lines.append(f"  - {p.path} (type={p.type}, required={p.required}){enum}: {(p.description or '')[:160]}")
    return "\n".join(lines)


def classify_tool(tool, cache_dir: Path | None = None, max_attempts: int = 3) -> dict:
    """返回 {param_path: [ {type, confidence, reason} ]}，仅含合法 sink 类型。"""
    cache_file = None
    if cache_dir:
        cache_dir = Path(cache_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / f"{_tool_key(tool)}.json"
        if cache_file.exists():
            return json.loads(cache_file.read_text())

    result: dict = {}
    for attempt in range(1, max_attempts + 1):
        try:
            raw = _parse(_call([{"role": "system", "content": SYSTEM},
                                {"role": "user", "content": _user_content(tool)}]))
            valid_paths = {p.path for p in tool.params}
            for path, labels in raw.items():
                if path not in valid_paths or not isinstance(labels, list):
                    continue
                clean = []
                for lab in labels:
                    t = str(lab.get("type", "")).strip()
                    if t in SINK_TYPES and t != "none":
                        clean.append({"type": t,
                                      "confidence": "high" if str(lab.get("confidence")) == "high" else "low",
                                      "reason": str(lab.get("reason", ""))[:200]})
                result[path] = clean
            break
        except Exception:
            if attempt == max_attempts:
                result = {}   # 失败则留空，规则层仍会兜底
    if cache_file is not None:
        cache_file.write_text(json.dumps(result, ensure_ascii=False))
    return result
