"""Sequence-construction agent (LangGraph version): runs a standard ReAct agent live to produce a call
sequence (Plan) that reaches the target tool.

See the sequence-construction agent design doc.
- Framework: langgraph's prebuilt ReAct agent + langchain-mcp-adapters (connecting the target MCP tools to the
  agent) + ChatOpenAI (via the project relay). The framework handles the "call -> observe -> decide next" loop;
  we provide the **goal/boundary prompt, exit budget, recipe extraction from the execution trace, and the
  reachability verdict**.
- Boundary: use **benign values only** to bring the target tool to a "legally callable" ready state — no
  payload injection, no vulnerability judgement (constrained by the system prompt).
- The discovery phase builds its own MCP connection (separate from the attack session); the resulting Plan (the
  recorded recipe) is handed to executor for deterministic replay in the attack session.
- Exit: recursion_limit as a hard budget; the prompt asks to "stop once the target calls through / explain if
  unreachable"; **reachability is judged by the execution trace** (whether the target tool was successfully
  called), not by the LLM's self-report.
- When langgraph is unavailable or errors, fall back to planner's one-shot planning / schema fallback.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from calchas.llm_failover import AllModelsUnavailable
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


def _sanitize_tool_names(tools) -> dict:
    """Normalize tool names into OpenAI function names (only [a-zA-Z0-9_-] allowed, length <=64), **rewriting
    each tool.name in place**, and return {sanitized_name: original_name}.

    Why it is safe: when langchain-mcp-adapters actually calls MCP it uses the original tool.name captured in
    the closure (request.name -> session.call_tool(request.name)), unrelated to StructuredTool.name; changing
    .name only affects the function name sent to the LLM. Why it is necessary: MCP/gateway tool names often
    contain dots (e.g. the gateway prefix io.github.X_Y-tool), and an OpenAI function name disallows dots — a
    dotted name is rejected by the relay with 502, paralyzing the whole sequence-construction agent. Handles
    any illegal character generically, not targeted at any specific server."""
    mapping: dict = {}
    for t in tools:
        orig = t.name
        san = re.sub(r"[^a-zA-Z0-9_-]", "_", orig)[:64] or "tool"
        if san in mapping:                       # collision after normalization (e.g. a.b and a_b) -> add a suffix to deduplicate
            base, i = san, 1
            while san in mapping:
                suf = f"_{i}"
                san = base[: 64 - len(suf)] + suf
                i += 1
        mapping[san] = orig
        t.name = san
    return mapping


def _goal(target_tool, display_name=None) -> str:
    req = [p.path for p in target_tool.params if p.required]
    lines = [f"TARGET tool to make callable: {display_name or target_tool.name}",
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
    """Reconstruct a time-ordered list of (tool, args, result_text, is_error) from the message trace."""
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


def _arg_spec(param_name, value, prior_results):
    """Decide whether a parameter is recorded as a "literal" or a "dependency edge (from_step)" in the recipe:
    if the value **appears in some earlier step's successful response** (= a dynamic value, e.g. a session_id
    returned by creating a session) -> record it as from_step, so on replay extract_value re-fetches it from
    that step's **current** response, avoiding a stale literal (see item ④ / the sequence-construction agent
    design doc). Otherwise record a literal. Enabled only for sufficiently long / non-trivial values, to avoid
    mis-matching '1'/'true'."""
    sval = str(value)
    if len(sval) >= 6 and not isinstance(value, bool):
        for step_no, rtext in prior_results:
            if rtext and sval in str(rtext):
                return {"src": "from_step", "step": step_no,
                        "extract": f"{param_name} (value looks like '{sval[:48]}')"}
    return {"src": "literal", "value": value}


def _build_plan_from_calls(target_name, calls, target_tool) -> Plan:
    """Assemble the agent trace's successful calls into a recipe: the successful prerequisites (non-target) + one
    step for the target tool, with the last step always being the target tool.

    Parameters are recorded by value by default; but if a parameter's value comes from an earlier step's
    response (a dynamic value, e.g. a new session's session_id) -> record it as a from_step dependency edge,
    re-fetched on replay, avoiding a "stale literal" (a literal is invalidated when the session resets / a token expires).
    """
    good = [(t, a, r) for (t, a, r, err) in calls if not err]
    pre = [(t, a, r) for (t, a, r) in good if t != target_name]
    tgt_ok = [(t, a) for (t, a, _r) in good if t == target_name]
    tgt_any = [(t, a) for (t, a, _r, _e) in calls if t == target_name]

    steps = []
    prior_results = []   # [(step_no, response_text)], earlier steps only, for from_step back-linking
    for (t, a, r) in pre:
        sno = len(steps) + 1
        steps.append(Step(sno, t, {k: _arg_spec(k, v, prior_results) for k, v in a.items()}))
        prior_results.append((sno, r))

    # Target tool arguments: prefer the successful call's, then any attempted, finally the schema fallback
    if tgt_ok:
        targs = tgt_ok[0][1]
    elif tgt_any:
        targs = tgt_any[-1][1]
    else:
        targs = {p.path: planner._fallback_literal(p) for p in target_tool.params if p.required}
    steps.append(Step(len(steps) + 1, target_name,
                      {k: _arg_spec(k, v, prior_results) for k, v in targs.items()}))

    target_confirmed = bool(tgt_ok)   # whether the agent actually got the target to call through (for the note only, NOT Plan.reachable)
    note = (f"agent reached the target ({len(pre)} prerequisite steps)" if target_confirmed
            else f"agent did not confirm the target was callable, best-effort replay ({len(pre)} prerequisite steps)")
    # Always optimistic replay: return reachable=True even when the agent could not confirm the target, so the
    # executor opens a session and judges real reachability from its own baseline. Returning reachable=False here
    # would make run_tool SKIP the tool without even trying, hurting recall on best-effort plans that still work.
    return Plan(steps=steps, reachable=True, note=note)


def _is_provider_down(err) -> bool:
    """Distinguish a "credential/account-level persistent failure" from a "per-tool transient failure".

    This ChatOpenAI path for sequence construction has **no** three-tier switching like chat() does; if the
    inner code merely swallows the exception it mindlessly falls back to a schema single step (fallback (no LLM)).
    But by HTTP semantics, 401 (unauthorized) / 402 (payment required) / 403 (forbidden, incl. insufficient
    balance) mean **this key itself is dead**, unrelated to the specific target — every subsequent tool will
    fail, and continuing is a fake run. These must **bubble up** so the upper layer switches to chat() or pauses
    if all are down; whereas recursion-limit / transient 429 / parse errors are per-tool/transient issues and can
    still degrade. The criterion only looks at generic HTTP status codes, not bound to any vendor/service."""
    code = getattr(err, "status_code", None)
    if code is None:
        code = getattr(err, "code", None)
    try:
        if int(code) in (401, 402, 403):
            return True
    except (TypeError, ValueError):
        pass
    return bool(re.search(r"Error code:\s*40[123]\b", str(err)))


async def _run_langgraph(url, headers, target_tool, catalog, settings, reporter) -> Plan:
    from langchain_mcp_adapters.client import MultiServerMCPClient
    from langchain_mcp_adapters.tools import load_mcp_tools
    from langgraph.prebuilt import create_react_agent

    model = _make_model(settings)
    conn = {"url": url, "transport": "streamable_http"}
    if headers:
        conn["headers"] = headers
    client = MultiServerMCPClient({"target": conn})

    rounds = max(1, getattr(settings, "agent_rounds", 6) if settings else 6)
    recursion = max(10, rounds * 6)

    # Persistent session: tools bound to the same MCP session, so state like set_working_dir is retained throughout the exploration
    async with client.session("target") as session:
        tools = await load_mcp_tools(session)
        # P1: MCP/gateway tool names often contain dots and other characters illegal in an OpenAI function name
        # (which allows only [a-zA-Z0-9_-]; a dotted name is rejected by the relay with 502 -> sequence
        # construction fully stalls). Normalize tool names at the LLM boundary, then map the call trace back to
        # the real names; the actual MCP call still uses the original name, unaffected.
        name_map = _sanitize_tool_names(tools)   # {sanitized_name: original_name}
        # The target's display name on the LLM side = its sanitized name; if the catalog name and the adapter
        # name happen to diverge and miss the mapping, also fall back to the "sanitized target name" (not the
        # dotted original), ensuring what is handed to the LLM is always a valid function name.
        target_disp = next((s for s, o in name_map.items() if o == target_tool.name), None) \
            or (re.sub(r"[^a-zA-Z0-9_-]", "_", target_tool.name)[:64] or "tool")
        agent = create_react_agent(model, tools, prompt=SYSTEM)
        last = None
        try:
            async for chunk in agent.astream({"messages": [("user", _goal(target_tool, target_disp))]},
                                             config={"recursion_limit": recursion},
                                             stream_mode="values"):
                last = chunk
        except Exception as e:
            reporter.emit("agent.limit", level="debug", tool=target_tool.name, error=str(e)[:200])
            if _is_provider_down(e):
                # Credential/balance-level persistent failure: do not fall back to a schema single step here (that
                # would be a fake run); bubble up to build_sequence -> first try chat()'s three-tier switching,
                # and only if all are down -> AllModelsUnavailable -> the batch layer pauses gracefully (resumable with --resume).
                raise

    messages = (last or {}).get("messages", []) if isinstance(last, dict) else []
    calls = _extract_calls(messages)
    calls = [(name_map.get(t, t), a, r, e) for (t, a, r, e) in calls]   # sanitized name -> real tool name
    reporter.emit("agent.done", level="debug", tool=target_tool.name, calls=len(calls))
    if not calls:
        return planner.fallback_plan(target_tool)   # the agent did not get a single call through -> schema fallback single-step plan
    return _build_plan_from_calls(target_tool.name, calls, target_tool)


_MODEL = None
_MODEL_PROVIDER = None   # records the provider name _MODEL is currently bound to; rebuild if the provider changed after failover


def reset_model():
    """Discard the process-reused ChatOpenAI singleton. After a per-tool timeout interrupt, the agent's
    persistent event loop is discarded entirely (see core._reset_agent_loop_after_abort); this singleton's httpx
    client is bound to the old loop and must be reset along with it, otherwise the next tool reuses a client
    bound to a closed loop -> 'Event loop is closed' (P7)."""
    global _MODEL, _MODEL_PROVIDER
    _MODEL = None
    _MODEL_PROVIDER = None


def _make_model(settings):
    """Return the process-reused ChatOpenAI singleton, **always built from llm_failover.agent_provider() (minimax)**.

    Why a singleton: ChatOpenAI's httpx async client binds to the event loop at first use (i.e. the persistent
    agent event loop, see core._AGENT_LOOP); reusing one across all tools/servers is fine; if a new ChatOpenAI
    were created per tool, a large number of httpx clients (sockets/FDs) would accumulate on that loop until the
    process exits.

    Why always minimax: this ChatOpenAI path does **not** do three-tier cascading fallback within a single agent
    run, so once the primary model ai-pixel hits 429, the whole sequence construction falls back to a schema
    single step (fallback (no LLM)). So it is bound to the most stable model that has been verified to support
    function calling, minimax (see llm_config.AGENT_PROVIDER_NAME). Sink inference / planning still go through
    chat()'s three-tier switching (ai-pixel -> deepseek -> minimax), decoupled from this and not interfering."""
    global _MODEL, _MODEL_PROVIDER
    from calchas import llm_failover
    prov = llm_failover.agent_provider()
    if _MODEL is not None and _MODEL_PROVIDER == prov["name"]:
        return _MODEL
    from langchain_openai import ChatOpenAI
    # base_url looks like .../v1/chat/completions; ChatOpenAI needs .../v1 (it appends /chat/completions itself)
    base = prov["base_url"]
    for suf in ("/chat/completions", "/chat/completions/"):
        if base.endswith(suf):
            base = base[: -len(suf)]
            break
    timeout = getattr(settings, "timeout", None) or 60.0
    # No temperature set: this relay is sensitive to temperature; probing confirmed the default works and supports tool calling
    _MODEL = ChatOpenAI(base_url=base, api_key=prov["api_key"], model=prov["model"],
                        timeout=max(timeout, 60.0), max_retries=1)
    _MODEL_PROVIDER = prov["name"]
    return _MODEL


async def build_sequence(url, headers, target_tool, catalog, settings, reporter, cache_dir=None) -> Plan:
    """Produce a sequence (Plan) that makes target_tool legally callable. Prefer the LangGraph agent; fall back to one-shot planning if unavailable/erroring."""
    cf = _cache_file(cache_dir, catalog.server_name, target_tool.name)
    if cf and cf.exists():
        reporter.emit("agent.cache_hit", level="debug", tool=target_tool.name)
        return _plan_from_dict(json.loads(cf.read_text()))

    try:
        plan = await _run_langgraph(url, headers, target_tool, catalog, settings, reporter)
    except AllModelsUnavailable:
        raise   # all models down: do not degrade to the schema fallback, bubble up so the batch layer pauses detection
    except Exception as e:
        reporter.emit("agent.error", level="debug", tool=target_tool.name, error=str(e)[:200])
        # Fallback: LLM one-shot planning (planner goes through llm_failover, which auto-switches to a backup and
        # moves the cursor to a working model, so the next tool's agent switches accordingly); if even planning
        # fails on all models -> AllModelsUnavailable bubbles up to pause.
        try:
            plan = planner.plan(target_tool, catalog) if (settings is None or settings.llm_plan) \
                else planner.fallback_plan(target_tool)
        except AllModelsUnavailable:
            raise
        except Exception:
            plan = planner.fallback_plan(target_tool)

    if cf:
        cf.write_text(json.dumps(_plan_to_dict(plan), ensure_ascii=False))
    return plan
