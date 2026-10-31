"""序列构建智能体（LangGraph 版）：用标准 ReAct 智能体实跑，产出到达目标工具的调用序列（Plan）。

见 docs/序列构建智能体设计.md。
- 框架：langgraph 预制 ReAct 智能体 + langchain-mcp-adapters（把目标 MCP 工具接入智能体）+
  ChatOpenAI（走项目中转）。框架负责"调用→看返回→决定下一步"的循环；我们负责**目标/边界提示、
  退出预算、从执行轨迹抽配方、可达裁决**。
- 边界：只用**良性值**把目标工具带到"能合法调用"的就绪状态——不注入载荷、不判漏洞（system 提示约束）。
- 发现阶段自建 MCP 连接（与攻击会话分离）；产物 Plan（录制的配方）交给 executor 在攻击会话里确定性回放。
- 退出：recursion_limit 作硬预算；提示里要求"能调通目标就停 / 不可达就说明"；**可达与否以执行轨迹为准**
  （目标工具是否被成功调用），不取 LLM 自述。
- langgraph 不可用或出错时，回退到 planner 一次性规划 / schema 兜底。
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import planner
from .types import Plan, Step

SYSTEM = """You are a setup assistant for black-box API testing. Your ONLY job is to make a TARGET tool
callable with VALID, BENIGN arguments by exploring the available tools.

Rules:
- Use ONLY benign, realistic values. NEVER use injection payloads, shell metacharacters, path traversal,
  or anything malicious — this is setup, not attack.
- Many required parameters cannot be invented (ids/paths/refs that must exist). Call other tools first to
  create or obtain what the target needs (e.g. set a working dir, init/clone a repo, create a resource),
  then call the target.
- When you can successfully call the TARGET tool with all required parameters, CALL IT ONCE (benignly) to
  confirm it works, then STOP and briefly say "reached".
- If, after reasonable attempts, the target cannot be made callable (a required value cannot be produced by
  any tool, or access is denied), STOP and briefly explain why ("unreachable: ...").
- Keep it short; do not call unrelated tools."""


def _goal(target_tool) -> str:
    req = [p.path for p in target_tool.params if p.required]
    lines = [f"TARGET tool to make callable: {target_tool.name}",
             f"description: {(target_tool.description or '')[:400]}",
             f"required parameters: {req or '(none)'}", "parameters:"]
    for p in target_tool.params:
        lines.append(f"  - {p.path} (type={p.type}, required={p.required}): {(p.description or '')[:120]}")
    lines.append("\nExplore and make this tool callable with benign values, then call it once and stop.")
    return "\n".join(lines)


def _cache_file(cache_dir, server_name, tool_name):
    if not cache_dir:
        return None
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    key = hashlib.sha256(f"{server_name}|{tool_name}".encode()).hexdigest()[:16]
    return cache_dir / (key + ".json")


def _plan_to_dict(p: Plan) -> dict:
    return {"steps": [vars(s) for s in p.steps], "reachable": p.reachable, "note": p.note}


def _plan_from_dict(d: dict) -> Plan:
    return Plan([Step(**s) for s in d["steps"]], d.get("reachable", True), d.get("note", ""))


def _extract_calls(messages) -> list:
    """从消息轨迹还原 (tool, args, result_text, is_error) 的时间序列表。"""
    from langchain_core.messages import ToolMessage
    pending: dict = {}
    calls = []
    for m in messages:
        for tc in (getattr(m, "tool_calls", None) or []):
            tid = tc.get("id") or f"{tc.get('name')}:{len(pending)}"
            pending[tid] = (tc.get("name"), tc.get("args") or {})
        if isinstance(m, ToolMessage):
            tid = getattr(m, "tool_call_id", None)
            if tid in pending:
                tool, args = pending.pop(tid)
                is_err = getattr(m, "status", "success") == "error"
                calls.append((tool, args, str(m.content), is_err))
    return calls


def _build_plan_from_calls(target_name, calls, target_tool) -> Plan:
    """把智能体轨迹里的成功调用拼成配方：成功的前置（非目标）+ 目标工具一步，末步必为目标工具。

    参数一律按 literal 录制（回放时照用这组走通过的良性值；服务端文件/资源态在同机持久，可复现）。
    """
    good_pre = [(t, a) for (t, a, _r, err) in calls if (not err) and t != target_name]
    target_ok = [(t, a) for (t, a, _r, err) in calls if (not err) and t == target_name]
    target_any = [(t, a) for (t, a, _r, _e) in calls if t == target_name]

    steps = []
    for i, (t, a) in enumerate(good_pre, 1):
        steps.append(Step(i, t, {k: {"src": "literal", "value": v} for k, v in a.items()}))

    # 目标工具实参：优先用成功那次的，其次用任意尝试过的，最后 schema 兜底
    if target_ok:
        targs = target_ok[0][1]
    elif target_any:
        targs = target_any[-1][1]
    else:
        targs = {p.path: planner._fallback_literal(p) for p in target_tool.params if p.required}
    steps.append(Step(len(steps) + 1, target_name,
                      {k: {"src": "literal", "value": v} for k, v in targs.items()}))

    reachable = bool(target_ok)
    note = (f"智能体走通目标（前置 {len(good_pre)} 步）" if reachable
            else f"智能体未确认目标调通，按best-effort回放（前置 {len(good_pre)} 步）")
    return Plan(steps=steps, reachable=True, note=note)   # 乐观回放；真实可达由 executor 基线判定


async def _run_langgraph(url, headers, target_tool, catalog, settings, reporter) -> Plan:
    from langchain_mcp_adapters.client import MultiServerMCPClient
    from langchain_mcp_adapters.tools import load_mcp_tools
    from langgraph.prebuilt import create_react_agent

    model = _make_model(settings)
    conn = {"url": url, "transport": "streamable_http"}
    if headers:
        conn["headers"] = headers
    client = MultiServerMCPClient({"target": conn})

    rounds = max(1, getattr(settings, "agent_rounds", 4) if settings else 4)
    recursion = max(10, rounds * 6)

    # 持久会话：工具绑定到同一个 MCP 会话，set_working_dir 这类状态在整个探索过程中保留
    async with client.session("target") as session:
        tools = await load_mcp_tools(session)
        agent = create_react_agent(model, tools, prompt=SYSTEM)
        last = None
        try:
            async for chunk in agent.astream({"messages": [("user", _goal(target_tool))]},
                                             config={"recursion_limit": recursion},
                                             stream_mode="values"):
                last = chunk
        except Exception as e:
            reporter.emit("agent.limit", level="debug", tool=target_tool.name, error=str(e)[:200])

    messages = (last or {}).get("messages", []) if isinstance(last, dict) else []
    calls = _extract_calls(messages)
    reporter.emit("agent.done", level="debug", tool=target_tool.name, calls=len(calls))
    if not calls:
        return planner.fallback_plan(target_tool)   # 智能体一步没调起来 → schema 兜底单步计划
    return _build_plan_from_calls(target_tool.name, calls, target_tool)


def _make_model(settings):
    from langchain_openai import ChatOpenAI
    from mcpfuzz.llm_config import API_KEY, BASE_URL, MODEL
    # BASE_URL 形如 .../v1/chat/completions；ChatOpenAI 需要 .../v1（会自己拼 /chat/completions）
    base = BASE_URL
    for suf in ("/chat/completions", "/chat/completions/"):
        if base.endswith(suf):
            base = base[: -len(suf)]
            break
    timeout = getattr(settings, "timeout", None) or 60.0
    # 不设 temperature：该中转对 temperature 敏感；探测已确认缺省可用且支持工具调用
    return ChatOpenAI(base_url=base, api_key=API_KEY, model=MODEL,
                      timeout=max(timeout, 60.0), max_retries=1)


async def build_sequence(url, headers, target_tool, catalog, settings, reporter, cache_dir=None) -> Plan:
    """产出让 target_tool 可合法调用的序列（Plan）。优先 LangGraph 智能体；不可用/出错回退一次性规划。"""
    cf = _cache_file(cache_dir, catalog.server_name, target_tool.name)
    if cf and cf.exists():
        reporter.emit("agent.cache_hit", level="debug", tool=target_tool.name)
        return _plan_from_dict(json.loads(cf.read_text()))

    try:
        plan = await _run_langgraph(url, headers, target_tool, catalog, settings, reporter)
    except Exception as e:
        reporter.emit("agent.error", level="debug", tool=target_tool.name, error=str(e)[:200])
        # 回退：大模型一次性规划（或 schema 兜底）
        try:
            plan = planner.plan(target_tool, catalog) if (settings is None or settings.llm_plan) \
                else planner.fallback_plan(target_tool)
        except Exception:
            plan = planner.fallback_plan(target_tool)

    if cf:
        cf.write_text(json.dumps(_plan_to_dict(plan), ensure_ascii=False))
    return plan
