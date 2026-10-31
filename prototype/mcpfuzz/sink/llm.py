"""大模型层：按工具**单次**推断每个参数的注入类别抬升。复用中转，带本地缓存。

设计要点（见 docs/Sink推断模块设计.md）：
- 按工具一次性判（该工具所有参数 + 全部类别一起），不多次采样（太费时且非必要——
  地板 + 规则并集已提供召回安全网）。
- 逐类独立打分、先推理后结论、**强制引用描述/schema 原文**作依据（引不出原话 → 不抬）。
- 置信分 low / medium / high 三档，映射到权重档位。
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

from mcpfuzz.llm_config import API_KEY, BASE_URL, MODEL

from .types import SINK_TYPES

SYSTEM = """You label MCP tool parameters for black-box server-side injection testing.
For each parameter, decide which dangerous operation(s) ("sink") its value plausibly flows into. Use ONLY these sink types:
- command_injection: value reaches an OS shell / command execution
- argument_injection: value becomes a command-line argument/flag of an invoked program
- path_traversal: value is used as a filesystem path
- ssrf: value becomes a URL/host the server will request
- query_injection: value is interpolated into a database/query language (SQL/NoSQL/Cypher/KQL/GraphQL)
- code_injection: value is evaluated as code or a template (eval/exec/Jinja/etc.)

Method (follow it, do not skip):
1. First state briefly what the TOOL does, from its name and description.
2. Then, for EACH parameter, reason about where its value could end up, and assign EACH applicable sink independently.
3. Judge by what the TOOL does, not just the parameter name: an innocuous-looking parameter can be a sink if the tool performs system/file/network/database operations with it.
4. GROUND every label: you MUST quote the exact phrase from the tool/parameter description (or a schema field) that supports it, in "evidence". If you cannot cite a supporting phrase, DO NOT emit that label.
5. Confidence: "high" (description/schema clearly implies this operation), "medium" (strongly suggested), "low" (plausible but weak).

A parameter may map to several sinks, or to none (emit []).
Return ONLY a JSON object mapping each parameter path to a list:
{ "<param_path>": [ {"type": "...", "confidence": "high|medium|low", "evidence": "<quoted phrase>"} ], ... }
Output nothing but the JSON."""


def _call(messages, timeout=120) -> str:
    payload = json.dumps({"model": MODEL, "messages": messages, "max_tokens": 2000})
    # 用 curl：该中转在部分环境下 python urllib 的 SSL 会失败；且不传 temperature（会 502），
    # 所以无法靠 temperature=0 求稳，稳定性由本地缓存 + 地板 + 规则并集保证。
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
    lines = [f"tool: {tool.name}", f"description: {(tool.description or '')[:800]}", "parameters:"]
    for p in tool.params:
        enum = f" enum={p.enum[:6]}" if p.enum else ""
        lines.append(f"  - {p.path} (type={p.type}, required={p.required}){enum}: {(p.description or '')[:200]}")
    return "\n".join(lines)


def _norm_conf(v) -> str:
    v = str(v).strip().lower()
    return v if v in ("low", "medium", "high") else "low"


def classify_tool(tool, cache_dir: Path | None = None, max_attempts: int = 3) -> dict:
    """返回 {param_path: [ {type, confidence(low/medium/high), evidence} ]}，仅含合法 sink 类型。"""
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
                    if not isinstance(lab, dict):
                        continue
                    t = str(lab.get("type", "")).strip()
                    if t in SINK_TYPES and t != "none":
                        clean.append({"type": t,
                                      "confidence": _norm_conf(lab.get("confidence")),
                                      "evidence": str(lab.get("evidence", lab.get("reason", "")))[:200]})
                result[path] = clean
            break
        except Exception:
            if attempt == max_attempts:
                result = {}   # 失败则留空，规则层仍会兜底
    if cache_file is not None:
        cache_file.write_text(json.dumps(result, ensure_ascii=False))
    return result
