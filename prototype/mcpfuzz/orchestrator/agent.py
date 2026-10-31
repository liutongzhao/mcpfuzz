"""序列构建智能体：闭环实跑（规划 → 执行 → 读错 → 修复）产出到达目标工具的调用序列（Plan）。

见 docs/序列构建智能体设计.md。
- 自包含循环（未引入 LangGraph）：复用 driver 调工具、llmclient 决策、planner 的计划格式、
  executor 的回放。只用**良性值**把目标工具带到"能合法调用"的就绪状态——不注入载荷、不判漏洞。
- 产物是 Plan（= 录制的配方，literal / from_step 依赖边齐全），交给 executor 确定性回放。
- 退出机制（非机械数次数）：目标相对进展（凑齐目标必填参数的比例）为主信号，叠加
  错误语义早退（终止类错误）、停滞、循环（重复同一计划），硬轮次兜底。每种退出带 reason。
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from mcpfuzz.driver import call_on
from mcpfuzz.llmclient import complete

from . import planner
from .extract import extract_value
from .types import Plan, Step

# 终止类错误：再试也没用，立即判不可达
_TERMINAL_KEYS = ("unauthorized", "forbidden", "permission denied", "authentication",
                  "not authorized", "method not found", "tool not found", "unknown tool",
                  "no such tool", "disabled", "not implemented", "access denied")

REPAIR_SYSTEM = planner.SYSTEM + """

You previously proposed a plan; executing it live revealed problems (shown as EXECUTION FEEDBACK).
Revise the plan to fix them: pick different prerequisite tools, change literal values, or adjust which
step produces a needed value. If after reflection no tool can produce a required value, set reachable:false.
Output ONLY the revised plan JSON."""


def _resolve(arg_specs: dict, step_responses: dict):
    args, missing = {}, []
    for param, spec in (arg_specs or {}).items():
        if not isinstance(spec, dict):
            continue
        if spec.get("src") == "from_step":
            resp = step_responses.get(spec.get("step"))
            val = extract_value(resp or "", spec.get("extract", "")) if resp is not None else None
            (args.__setitem__(param, val) if val is not None else missing.append(param))
        else:
            args[param] = spec.get("value")
    return args, missing


async def _safe(session, tool, args) -> dict:
    try:
        return await call_on(session, tool, args)
    except Exception as e:
        return {"text": "", "is_error": True, "exc": repr(e)}


def _terminal_error(text: str) -> str | None:
    low = (text or "").lower()
    for k in _TERMINAL_KEYS:
        if k in low:
            return k
    return None


def _plan_sig(plan: Plan) -> str:
    return hashlib.sha256(
        json.dumps([(s.tool, s.args) for s in plan.steps], ensure_ascii=False, sort_keys=True,
                   default=str).encode()).hexdigest()[:16]


def _history_text(trace: list) -> str:
    out = []
    for tool, args, is_err, text in trace[-8:]:
        tag = "ERROR" if is_err else "ok"
        out.append(f"- {tool}({json.dumps(args, ensure_ascii=False, default=str)[:200]}) -> {tag}: "
                   f"{(text or '')[:200]}")
    return "\n".join(out) or "(no calls yet)"


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


async def build_sequence(session, target_tool, catalog, settings, reporter, cache_dir=None) -> Plan:
    """闭环探索出一条让 target_tool 可合法调用的序列（Plan）。失败则 Plan(reachable=False, note=reason)。"""
    cf = _cache_file(cache_dir, catalog.server_name, target_tool.name)
    if cf and cf.exists():
        reporter.emit("agent.cache_hit", level="debug", tool=target_tool.name)
        return _plan_from_dict(json.loads(cf.read_text()))

    required = [p.path for p in target_tool.params if p.required]
    rounds = max(1, getattr(settings, "agent_rounds", 4) if settings else 4)
    tool_names = {t.name for t in catalog.tools}

    # 初始假设计划
    try:
        plan = planner.plan(target_tool, catalog)
    except Exception:
        plan = planner.fallback_plan(target_tool)

    trace: list = []
    seen: set = set()
    best_resolved = -1
    stagnation = 0
    result = None

    for rnd in range(1, rounds + 1):
        sig = _plan_sig(plan)
        if sig in seen:          # 循环：重复同一计划 → 停
            result = Plan(plan.steps, False, f"序列构建停滞（第{rnd}轮重复同一计划）")
            break
        seen.add(sig)

        # 执行前置（良性）
        step_responses: dict = {}
        errors: list = []
        for st in plan.steps[:-1]:
            args, missing = _resolve(st.args, step_responses)
            if missing:
                errors.append(f"步骤{st.step}({st.tool})参数{missing}未能从前置取值")
                continue
            res = await _safe(session, st.tool, args)
            step_responses[st.step] = res.get("text", "")
            trace.append((st.tool, args, res["is_error"], res.get("text", "")))
            if res["is_error"]:
                term = _terminal_error(res.get("text") or res.get("exc", ""))
                errors.append(f"步骤{st.step}({st.tool})报错: {(res.get('text') or res.get('exc') or '')[:150]}")
                if term:
                    result = Plan(plan.steps, False, f"遇终止类错误[{term}]，判不可达（步骤{st.tool}）")
                    break
        if result:
            break

        # 解析目标工具实参
        base_args, missing = _resolve(plan.steps[-1].args, step_responses)
        resolved = len(required) - len(set(missing) & set(required))
        reporter.emit("agent.round", level="debug", tool=target_tool.name, round=rnd,
                      resolved=resolved, required=len(required), errors="；".join(errors)[:300])

        if not missing:
            # 尝试用良性实参调目标工具：非报错即"就绪"（触达），返回这条计划作为配方
            res = await _safe(session, target_tool.name, base_args)
            trace.append((target_tool.name, base_args, res["is_error"], res.get("text", "")))
            if not res["is_error"]:
                result = Plan(plan.steps, True, f"智能体{rnd}轮走通")
                break
            term = _terminal_error(res.get("text") or res.get("exc", ""))
            if term:
                result = Plan(plan.steps, False, f"目标工具遇终止类错误[{term}]，判不可达")
                break
            errors.append(f"目标工具调用报错: {(res.get('text') or res.get('exc') or '')[:200]}")

        # 进展判定（目标相对进展为主信号）
        if resolved > best_resolved:
            best_resolved = resolved
            stagnation = 0
        else:
            stagnation += 1
        if stagnation >= 2:
            result = Plan(plan.steps, False,
                          f"序列构建停滞（目标必填参数仅凑齐 {max(best_resolved,0)}/{len(required)}）")
            break

        # 修复：把执行反馈喂回大模型，要一版修订计划
        if rnd < rounds and getattr(settings, "llm_plan", True):
            revised = _replan(target_tool, catalog, tool_names, trace, "；".join(errors)[:600])
            if revised is not None:
                plan = revised
                continue
        # 无法修复（无大模型/解析失败）→ 用当前计划收尾
        result = Plan(plan.steps, bool(not missing),
                      f"智能体{rnd}轮未走通：{'；'.join(errors)[:200] or '目标参数未凑齐'}")
        break

    if result is None:
        result = Plan(plan.steps, False, f"序列构建达轮次上限({rounds})仍未走通")

    reporter.emit("agent.done", level="debug", tool=target_tool.name,
                  reachable=result.reachable, note=result.note, steps=len(result.steps))
    if cf:
        cf.write_text(json.dumps(_plan_to_dict(result), ensure_ascii=False))
    return result


def _replan(target_tool, catalog, tool_names, trace, feedback):
    others = "\n".join(planner._describe_tool(t) for t in catalog.tools if t.name != target_tool.name)
    user = (f"{planner.EXAMPLE}\n\nTARGET tool:\n{planner._describe_tool(target_tool)}\n\n"
            f"Other tools:\n{others}\n\nEXECUTION FEEDBACK (live):\n{_history_text(trace)}\n"
            f"PROBLEM: {feedback}\n\nProduce the revised plan JSON.")
    try:
        return planner._validate(planner._parse(complete(REPAIR_SYSTEM, user, max_tokens=2000)),
                                 target_tool.name, tool_names)
    except Exception:
        return None
