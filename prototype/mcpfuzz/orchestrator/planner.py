"""规划器：大模型据(足量)描述假设一条到达目标工具的调用序列。带缓存与兜底。

计划是"假设"，运行时逐跳验证；最后一步即目标工具，其参数构成"发射台"。
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from mcpfuzz.llmclient import complete

from .types import Plan, Step

SYSTEM = """You plan a minimal call sequence that makes a TARGET MCP tool invocable, for black-box testing.
Some required parameters cannot be fabricated (opaque identifiers like ids/codes/tokens); their real values must come from the response of an earlier tool call. Other parameters can be given plausible literal values (coordinates, search text, names, booleans).

You are given the TARGET tool and the FULL catalog of other tools (names, descriptions, parameters). Infer which tool can PRODUCE a needed value from the descriptions, and plan the shortest sequence ending at the target tool.

Output ONLY a JSON object:
{
 "steps": [
   {"step": 1, "tool": "<name>", "args": {
       "<param>": {"src": "literal", "value": <value>},
       "<param>": {"src": "from_step", "step": <earlier step>, "extract": "<natural-language: what value to take from that step's response>"}
   }},
   ...
 ],
 "reachable": true,
 "note": ""
}
Rules:
- The LAST step MUST be the target tool, with all its parameters filled (use benign literals; these are just a valid baseline).
- Keep the sequence as short as possible; include a prerequisite step ONLY when a value truly cannot be fabricated.
- "extract" is a natural-language intent, NOT an assumed field name — do not assume the response structure.
- If a required value cannot be produced by any tool, set "reachable": false and explain in "note".
- Output nothing but the JSON."""

EXAMPLE = """Example — target tool `searchProductForMcp(deptId:int required, query:str required)`, catalog has `queryShopList(longitude, latitude)` described as returning nearby shops:
{"steps":[
  {"step":1,"tool":"queryShopList","args":{"longitude":{"src":"literal","value":121.47},"latitude":{"src":"literal","value":31.23}}},
  {"step":2,"tool":"searchProductForMcp","args":{"deptId":{"src":"from_step","step":1,"extract":"a shop's deptId / 门店ID"},"query":{"src":"literal","value":"coffee"}}}
],"reachable":true,"note":""}"""


def _fallback_literal(param):
    if param.default is not None:
        return param.default
    if param.example is not None:
        return param.example
    if param.enum:
        return param.enum[0]
    return {"string": "test", "integer": 1, "number": 1, "boolean": True,
            "array": [], "object": {}}.get(param.type, "test")


def _fallback_plan(target_tool) -> Plan:
    """大模型不可用/失败时：长度 1 计划，用 schema 值填满目标工具参数。"""
    args = {p.path: {"src": "literal", "value": _fallback_literal(p)} for p in target_tool.params}
    return Plan(steps=[Step(1, target_tool.name, args)], reachable=True, note="fallback(无大模型)")


def _describe_tool(t, full=True):
    lines = [f"- tool: {t.name}", f"  description: {(t.description or '')[:800]}"]
    for p in t.params:
        enum = f" enum={p.enum[:6]}" if p.enum else ""
        d = f" default={p.default!r}" if p.default is not None else ""
        lines.append(f"    param {p.path} (type={p.type}, required={p.required}){enum}{d}: {(p.description or '')[:200]}")
    return "\n".join(lines)


def _parse(text) -> dict:
    text = re.sub(r"```(?:json)?", "", text).strip()
    s, e = text.find("{"), text.rfind("}")
    if s == -1 or e <= s:
        raise ValueError("无 JSON")
    return json.loads(text[s:e + 1])


def _validate(data, target_name, tool_names) -> Plan:
    steps_raw = data.get("steps") or []
    if not steps_raw or steps_raw[-1].get("tool") != target_name:
        raise ValueError("计划末步不是目标工具")
    steps = []
    for i, s in enumerate(steps_raw, 1):
        if s.get("tool") not in tool_names:
            raise ValueError(f"未知工具 {s.get('tool')}")
        steps.append(Step(i, s["tool"], s.get("args") or {}))
    return Plan(steps=steps, reachable=bool(data.get("reachable", True)), note=str(data.get("note", "")))


def plan(target_tool, catalog, cache_dir: Path | None = None, max_attempts: int = 2) -> Plan:
    tool_names = {t.name for t in catalog.tools}
    key = None
    if cache_dir:
        cache_dir = Path(cache_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)
        key = cache_dir / (hashlib.sha256(
            f"{catalog.server_name}|{target_tool.name}".encode()).hexdigest()[:16] + ".json")
        if key.exists():
            d = json.loads(key.read_text())
            return Plan([Step(**s) for s in d["steps"]], d.get("reachable", True), d.get("note", ""))

    others = "\n".join(_describe_tool(t) for t in catalog.tools if t.name != target_tool.name)
    user = (f"{EXAMPLE}\n\nTARGET tool:\n{_describe_tool(target_tool)}\n\n"
            f"Other tools in this server:\n{others}\n\nProduce the plan JSON.")

    result = None
    for _ in range(max_attempts):
        try:
            result = _validate(_parse(complete(SYSTEM, user, max_tokens=2000)),
                               target_tool.name, tool_names)
            break
        except Exception:
            result = None
    if result is None:
        result = _fallback_plan(target_tool)

    if key is not None:
        key.write_text(json.dumps(
            {"steps": [vars(s) for s in result.steps], "reachable": result.reachable, "note": result.note},
            ensure_ascii=False))
    return result
