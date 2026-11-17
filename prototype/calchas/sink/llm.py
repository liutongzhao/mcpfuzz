"""LLM layer: infer each parameter's injection-class raise with a SINGLE call per tool. Reuses the
relay client, with a local cache.

Design notes (see the sink-inference design doc):
- Judge per tool in one shot (all of the tool's parameters + all classes together), without multiple
  sampling (too slow and unnecessary — the floor + rule union already provides a recall safety net).
- Score each class independently, reason first then conclude, and REQUIRE a quote from the
  description/schema as justification (if no original phrase can be cited -> do not raise).
- Confidence low / medium / high, mapped to weight tiers.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

from calchas.llm_config import API_KEY, BASE_URL, MODEL  # noqa: F401  (kept for compatibility; actual calls go through llm_failover)
from calchas.llm_failover import AllModelsUnavailable

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

Extra requirement for "code_injection" ONLY: when (and only when) you assign code_injection to a parameter,
add two extra keys to THAT label object, describing the parameter's DECLARED purpose (reading comprehension,
NOT a vulnerability judgement):
- "declared_domain": one short sentence paraphrasing what the tool/parameter says it evaluates
  (e.g. "evaluates a mathematical expression", "renders a chart spec", "runs user-provided Python code").
- "domain_evidence": the exact phrase quoted from the tool/parameter description or a schema field that supports it.
If you cannot quote a supporting phrase, set "declared_domain" to "" (empty). Do NOT guess the purpose.

Return ONLY a JSON object mapping each parameter path to a list:
{ "<param_path>": [ {"type": "...", "confidence": "high|medium|low", "evidence": "<quoted phrase>"} ], ... }
For a code_injection label the object additionally carries "declared_domain" and "domain_evidence".
Output nothing but the JSON."""


def _call(messages, timeout=120) -> str:
    # Goes through multi-model failover (see llm_failover): on failure the current model is swapped for a
    # backup; if all fail it raises AllModelsUnavailable. That exception is NOT swallowed by the rule
    # fallback below — it bubbles up so the batch layer pauses detection (resume with --resume after recovery).
    from calchas import llm_failover
    return llm_failover.chat(messages, max_tokens=2000, timeout=timeout)


def _parse(text) -> dict:
    text = re.sub(r"```(?:json)?", "", text).strip()
    s, e = text.find("{"), text.rfind("}")
    if s == -1 or e <= s:
        raise ValueError("response contains no JSON object")
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
    """Return {param_path: [ {type, confidence(low/medium/high), evidence} ]}, only valid sink types."""
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
                        entry = {"type": t,
                                 "confidence": _norm_conf(lab.get("confidence")),
                                 "evidence": str(lab.get("evidence", lab.get("reason", "")))[:200]}
                        if t == "code_injection":
                            # Declared domain + quote (policy B: annotation for manual review only,
                            # not part of the tool's automatic verdict).
                            entry["declared_domain"] = str(lab.get("declared_domain", ""))[:300]
                            entry["domain_evidence"] = str(lab.get("domain_evidence", ""))[:200]
                        clean.append(entry)
                result[path] = clean
            break
        except AllModelsUnavailable:
            raise   # all models down: do not degrade to the rule fallback; bubble up so the batch layer pauses
        except Exception:
            if attempt == max_attempts:
                result = {}   # occasional single-model failure (already tried backups via failover) -> leave empty, rule layer covers
    if cache_file is not None:
        cache_file.write_text(json.dumps(result, ensure_ascii=False))
    return result
