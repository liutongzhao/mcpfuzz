"""LLM classifier (the semantic arm of stage 1, used when LLM is on).

One call per tool. For each parameter the model decides, for each of four dangerous OPERATIONS, whether
the value can reach it (yes/no) — a deterministic multi-label classification, not scoring. The context is
deliberately rich: server name, the tool, the sibling tools on the same server, the other parameters of
this tool, and this parameter's schema constraints. The parameter NAME is a first-class signal (not only
the description).

Returns {param_path: {"operations": [op, ...], "evidence": {op: quote}, "declared_domain", "domain_evidence"}}.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from calchas.llm_failover import AllModelsUnavailable

from .types import OP_CODE, OPERATIONS

SYSTEM = """You classify a parameter of an MCP server tool for black-box server-side injection testing.
Your goal is RECALL: do not miss any dangerous operation the parameter's value could reach. Over-including is cheap (a wrong guess only wastes one test); omitting is costly (a missed operation means a real vulnerability is never tested). So be generous — list EVERY operation the value could plausibly reach.

The four dangerous operations (the value may reach one directly, after string concatenation, or after being handed to another program):
- external_program: the value is handed to an external program the server invokes (as a shell command, or as a command-line argument/flag of an invoked program).
- file_path: the value becomes, or becomes part of, a filesystem path the server reads or writes.
- network_address: the value becomes, or becomes part of, an address/URL the server sends a request to.
- code_eval: the value is evaluated as code or a template (eval/exec/template rendering).

How to decide (recall-first):
1. First state briefly what the TOOL does, using its name, description, and the sibling tools on the same server (e.g. a server whose tools are git_add/git_commit wraps the git command line; a server that runs adb/xcodebuild/kubectl invokes that CLI).
2. For EACH parameter, INCLUDE an operation whenever there is ANY plausible way the value reaches it. The parameter NAME alone is sufficient grounds — you do NOT need the description to say so. For example: a parameter named path/file/dir/filepath/output/dest almost always reaches file_path; url/uri/host/endpoint/src reaches network_address; an id/name/target/device/udid/version/repo handed to a CLI tool reaches external_program; an expr/code/spec/template reaches code_eval.
3. Only LEAVE OUT an operation when the value clearly CANNOT reach it — e.g. a boolean flag, an enum, a pure numeric count/limit, or a free-text field that is only stored or shown back and never used as a path/URL/command/code.
4. When unsure, INCLUDE it.
5. A value handed to an invoked program reaches external_program even if you cannot tell whether it is spliced into a shell string or passed as a separate argument — include it either way.

Return ONLY a JSON object mapping each parameter path to an object:
{ "<param_path>": { "operations": ["external_program", ...], "evidence": {"external_program": "<short reason, optional>", ...} } }
"evidence" is OPTIONAL — add a short reason when you have one, but NEVER drop an operation just because you cannot cite an exact phrase. For a code_eval operation, additionally add "declared_domain" (one short sentence paraphrasing what it evaluates, e.g. "evaluates a math expression") and "domain_evidence" (a supporting phrase, or ""). Output nothing but the JSON."""


def _call(messages, timeout=120) -> str:
    from calchas import llm_failover
    return llm_failover.chat(messages, max_tokens=2000, timeout=timeout)


def _parse(text) -> dict:
    text = re.sub(r"```(?:json)?", "", text).strip()
    s, e = text.find("{"), text.rfind("}")
    if s == -1 or e <= s:
        raise ValueError("response contains no JSON object")
    return json.loads(text[s:e + 1])


def _context_key(tool, target) -> str:
    sig = [getattr(target, "server_name", None),
           sorted(t.name for t in getattr(target, "tools", []) or []),
           tool.name, tool.description,
           [(p.path, p.type, p.description, p.enum, p.required,
             p.pattern, p.str_format, p.min_length, p.max_length) for p in tool.params]]
    return hashlib.sha256(json.dumps(sig, ensure_ascii=False, default=str).encode()).hexdigest()[:16]


def _param_line(p) -> str:
    bits = [f"type={p.type}", f"required={p.required}"]
    if p.enum:
        bits.append(f"enum={p.enum[:6]}")
    if p.str_format:
        bits.append(f"format={p.str_format}")
    if p.pattern:
        bits.append(f"pattern={p.pattern[:40]}")
    if p.min_length is not None or p.max_length is not None:
        bits.append(f"len={p.min_length}..{p.max_length}")
    return f"  - {p.path} ({', '.join(bits)}): {(p.description or '')[:200]}"


def _user_content(tool, target) -> str:
    lines = []
    if getattr(target, "server_name", None):
        lines.append(f"server: {target.server_name}")
    siblings = [t.name for t in (getattr(target, "tools", []) or []) if t.name != tool.name]
    if siblings:
        lines.append("other tools on this server: " + ", ".join(siblings[:40]))
    lines += [f"tool: {tool.name}", f"description: {(tool.description or '')[:800]}", "parameters:"]
    lines += [_param_line(p) for p in tool.params]
    return "\n".join(lines)


def classify_tool(tool, target=None, cache_dir: Path | None = None, max_attempts: int = 3) -> dict:
    """Return {param_path: {operations:[...], evidence:{...}, declared_domain?, domain_evidence?}}."""
    cache_file = None
    if cache_dir:
        cache_dir = Path(cache_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / f"{_context_key(tool, target)}.json"
        if cache_file.exists():
            return json.loads(cache_file.read_text())

    valid_paths = {p.path for p in tool.params}
    result: dict = {}
    for attempt in range(1, max_attempts + 1):
        try:
            raw = _parse(_call([{"role": "system", "content": SYSTEM},
                                {"role": "user", "content": _user_content(tool, target)}]))
            for path, obj in raw.items():
                if path not in valid_paths or not isinstance(obj, dict):
                    continue
                ops = [o for o in obj.get("operations", []) if o in OPERATIONS]
                ev = obj.get("evidence", {})
                entry = {"operations": ops,
                         "evidence": {o: str(ev.get(o, ""))[:200] for o in ops} if isinstance(ev, dict) else {}}
                if OP_CODE in ops:
                    entry["declared_domain"] = str(obj.get("declared_domain", ""))[:300]
                    entry["domain_evidence"] = str(obj.get("domain_evidence", ""))[:200]
                result[path] = entry
            break
        except AllModelsUnavailable:
            raise   # all models down: bubble up so the batch layer pauses (do not degrade)
        except Exception:
            if attempt == max_attempts:
                result = {}   # occasional single failure -> empty; parameter gets no class this run
    if cache_file is not None:
        cache_file.write_text(json.dumps(result, ensure_ascii=False))
    return result
