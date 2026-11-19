"""Orchestrator facade: chains the first four steps into a detection pipeline.

For each "tool with a sink": plan (once, cached) -> open a persistent session -> build the launch pad ->
send payloads per parameter and verify -> aggregate into Findings.
"""
from __future__ import annotations

import asyncio
import json
import signal
import time
from pathlib import Path

from calchas.driver import call_on, open_session, ping
from calchas.llm_failover import AllModelsUnavailable
from calchas.payload import PayloadSynthesizer

from . import agent, planner
from .executor import run_tool
from .types import SKIPPED, Finding, Plan

# The agent-exploration event loop: **process-level persistent** (one shared across all servers/Orchestrators).
# Why it cannot be created/closed per server: LangGraph's async LLM client (ChatOpenAI/httpx) caches the
# underlying connection on the event loop it is first used on; if each server swaps in a new loop and closes it
# after scanning, the next server's first agent call reuses a cached client still bound to the closed old loop
# -> "Event loop is closed", crashing every server's first multi-step sequence construction (P7).
# One process-level persistent loop fixes it at the root (the attack phase uses its own independent asyncio.run
# temporary loops, which do not interfere).
# Assumption: batch scanning is **serial** (the CLI loops over targets one by one), so at any moment only one
# _agent_run is running. If this is parallelized in the future, or used concurrently in a multithreaded host,
# it must switch to a per-thread loop or add reentrancy protection, otherwise "event loop is already running".
_AGENT_LOOP = None


def _get_agent_loop():
    global _AGENT_LOOP
    if _AGENT_LOOP is None or _AGENT_LOOP.is_closed():
        _AGENT_LOOP = asyncio.new_event_loop()
        # Invariant: a fresh loop must come with a fresh model. The ChatOpenAI singleton's httpx client binds to
        # the loop it was first used on; carrying it onto a new loop makes the next tool hit 'Event loop is closed'
        # (P7). _reset_agent_loop_after_abort already pairs loop+model on the timeout path, but the is_closed()
        # branch above has no such pairing -- enforcing it here, at the single place loops are born, closes that
        # gap for good without special-casing how the old loop died. Idempotent: no-op when the model is unset
        # (first call), so it is always safe.
        agent.reset_model()
    return _AGENT_LOOP


# --- per-tool total-time watchdog ------------------------------------------------------
# A hard time limit on the main thread via SIGALRM: when a tool (sequence construction + attack verdict)
# exceeds its budget, raise an interrupt, abandon that tool and move to the next, so one tool does not stall
# the whole batch. Only effective on a Unix main thread (which is the case inside the container); if it cannot
# be installed it gracefully degrades to "no per-tool timeout", without affecting detection itself.


class ToolBudgetExceeded(BaseException):
    """Per-tool budget-exceeded interrupt. **Deliberately subclasses BaseException** (not Exception): so the
    `except Exception` blocks in _explore_and_attack / _attack_tool do not swallow it, and it can bubble all the
    way up to the tool loop to be handled specially."""


def _raise_tool_budget(signum, frame):
    raise ToolBudgetExceeded()


def _arm_tool_alarm(seconds: float) -> bool:
    """Install a SIGALRM watchdog firing after `seconds`; return whether it was actually installed.
    budget <=0 / non-Unix / non-main-thread (signal.signal raises ValueError) -> return False, degrading to no watchdog."""
    if not seconds or seconds <= 0 or not hasattr(signal, "setitimer"):
        return False
    try:
        signal.signal(signal.SIGALRM, _raise_tool_budget)
        signal.setitimer(signal.ITIMER_REAL, seconds)
        return True
    except (ValueError, OSError):
        return False


def _disarm_tool_alarm(armed: bool) -> None:
    if not armed:
        return
    try:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
    except (ValueError, OSError):
        pass


def _reset_agent_loop_after_abort() -> None:
    """Called after a tool timeout interrupt. The agent's persistent event loop may be stopped half-way on an
    await (with a pending task / half-open socket); to be safe, discard it entirely and reset the ChatOpenAI
    singleton bound to it, so the next tool rebuilds with a fresh loop + client, avoiding a residual task or
    'Event loop is closed' polluting later tools. Only a real timeout pays this rebuild cost (very rare)."""
    global _AGENT_LOOP
    loop = _AGENT_LOOP
    _AGENT_LOOP = None
    try:
        agent.reset_model()
    except Exception:
        pass
    if loop is None or loop.is_closed():
        return
    try:
        for task in asyncio.all_tasks(loop):
            task.cancel()
    except Exception:
        pass
    try:
        loop.close()
    except Exception:
        pass


class _NullReporter:
    def emit(self, *a, **k):
        pass


class Orchestrator:
    def __init__(self, url, headers, catalog, oracle, cache_dir: str | Path | None = None,
                reporter=None, settings=None):
        """reporter: cli.events.Reporter; if not given, silent (the core can still be used as a library).
        settings: config.Settings, with knobs like llm_plan/poll_rounds/poll_interval/timeout/delay/max_payloads.
        """
        self.url = url
        self.headers = headers
        self.catalog = catalog
        self.oracle = oracle
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.synth = PayloadSynthesizer(oracle)
        self._tools_by_name = {t.name: t for t in catalog.tools}
        self._reader = _find_reader(catalog)   # cross_tool canary read-back tool (may be None)
        self.reporter = reporter or _NullReporter()
        self.settings = settings

    def run(self, param_sinks, only_tools=None, dry_run: bool = False) -> list:
        """param_sinks: list of sink.ParamSinkPrior. only_tools: restrict to a set of tool names (for debugging).
        dry_run: only produce plans, send no payloads (used by recon). Returns a list of Findings."""
        # Keep every non-inert parameter that has an enabled class (no gating by single label — the floor
        # guarantees every class is tested), grouped by tool
        by_tool: dict[str, list] = {}
        for ps in param_sinks:
            if only_tools and ps.tool not in only_tools:
                continue
            if not getattr(ps, "inert", False) and ps.classes:
                by_tool.setdefault(ps.tool, []).append(ps)
        return self._run_all(by_tool, dry_run)

    def _run_all(self, by_tool, dry_run) -> list:
        findings = []
        plan_cache = self.cache_dir / ".plan_cache" if self.cache_dir else None
        agent_cache = self.cache_dir / ".agent_cache" if self.cache_dir else None
        use_llm_plan = self.settings.llm_plan if self.settings else True
        use_agent = (getattr(self.settings, "sequence_agent", True) if self.settings else True) and use_llm_plan
        timeout = self.settings.timeout if self.settings else None
        retries = max(1, self.settings.retries) if self.settings else 3
        poll_window = (self.settings.poll_rounds, self.settings.poll_interval) if self.settings else (3, 2.0)
        tool_budget = float(getattr(self.settings, "tool_timeout", 0.0) or 0.0) if self.settings else 0.0
        total = len(by_tool)
        for idx, (tool_name, sink_params) in enumerate(by_tool.items(), 1):
            tool = self._tools_by_name.get(tool_name)
            if tool is None:
                continue
            if dry_run:
                # dry-run only previews the hypothesized plan (no real run, no agent), preserving the "no request was sent" semantics
                p = planner.plan(tool, self.catalog, cache_dir=plan_cache) if use_llm_plan \
                    else planner.fallback_plan(tool)
                self.reporter.emit("attack.plan", tool=tool_name, index=idx, total=total,
                                   steps=len(p.steps), reachable=p.reachable, note=p.note,
                                   param_count=len(sink_params))
                continue
            # Per-tool total-time watchdog: if sequence construction + attack verdict together exceed the budget,
            # abandon this tool, record it as not-tested, and move on — so one tool (most often a dependency chain
            # the agent's sequence construction cannot crack) does not stall the whole batch.
            t_tool = time.time()
            armed = _arm_tool_alarm(tool_budget)
            try:
                # Decide how the target becomes callable: a benign direct probe screens out independent tools
                # (single-step, no agent); a non-direct tool goes to the live-session agent (explore + attack on
                # ONE session, so the state the agent builds stays live for the attack — no two-session replay);
                # with the agent off, fall back to one-shot planning + replay.
                direct_plan = self._try_direct(tool) if use_llm_plan else None
                if direct_plan is not None:
                    self.reporter.emit("attack.plan", tool=tool_name, index=idx, total=total,
                                       steps=len(direct_plan.steps), reachable=direct_plan.reachable,
                                       note=direct_plan.note, param_count=len(sink_params))
                    findings += self._attack_tool(tool, direct_plan, sink_params, timeout, poll_window, retries)
                elif use_agent:
                    findings += self._explore_and_attack_sync(tool, sink_params, idx, total,
                                                              timeout, poll_window, agent_cache)
                else:
                    plan = planner.plan(tool, self.catalog, cache_dir=plan_cache) if use_llm_plan \
                        else planner.fallback_plan(tool)
                    self.reporter.emit("attack.plan", tool=tool_name, index=idx, total=total,
                                       steps=len(plan.steps), reachable=plan.reachable, note=plan.note,
                                       param_count=len(sink_params))
                    findings += self._attack_tool(tool, plan, sink_params, timeout, poll_window, retries)
            except ToolBudgetExceeded:
                findings += self._on_tool_timeout(tool_name, idx, total, t_tool, tool_budget, sink_params)
            except BaseException as e:   # noqa: BLE001
                # If the watchdog interrupt fires inside an MCP/anyio session (async with open_session), anyio
                # wraps it into a BaseExceptionGroup while cleaning up child tasks — a bare `except ToolBudgetExceeded`
                # cannot catch "the box containing it" and it would leak to the process level and crash the runner.
                # Here we unwrap the box: if the group contains the watchdog interrupt, finish the same as a
                # "per-tool timeout" and continue to the next; if not (a real error / KeyboardInterrupt etc.),
                # re-raise as-is, never swallow.
                budget_exc = None
                if isinstance(e, BaseExceptionGroup):
                    budget_exc, _rest = e.split(ToolBudgetExceeded)
                if budget_exc is None:
                    raise
                findings += self._on_tool_timeout(tool_name, idx, total, t_tool, tool_budget, sink_params)
            finally:
                _disarm_tool_alarm(armed)
        return findings

    def _on_tool_timeout(self, tool_name, idx, total, t_tool, tool_budget, sink_params) -> list:
        """Unified finish for a per-tool timeout: emit the event, discard the agent's residual event loop, and
        record all of the tool's parameters as SKIPPED (not tested). The watchdog interrupt comes here whether
        it was a bare ToolBudgetExceeded or wrapped by anyio into a BaseExceptionGroup."""
        elapsed = time.time() - t_tool
        note = f"per-tool timeout (budget {int(tool_budget)}s, used {elapsed:.0f}s), abandoned, moving to the next tool"
        self.reporter.emit("attack.tool.timeout", tool=tool_name, index=idx, total=total,
                           seconds=round(elapsed, 1), budget=tool_budget)
        _reset_agent_loop_after_abort()   # the agent's persistent loop may be stopped half-way; discard and rebuild to avoid polluting later tools
        return [Finding(tool_name, ps.param_path, _repr_class(ps), SKIPPED, note=note)
                for ps in sink_params]

    def _try_direct(self, tool):
        """Benign direct probe: call the target once with schema values. If it calls through, it is an
        independent tool — return a single-step plan (no sequence / agent needed); else None (needs a sequence).
        The most reliable generic criterion (no static dependency guessing, not targeted at any server), and it
        incidentally yields the "fraction of tools needing sequence construction" metric."""
        base_plan = planner.fallback_plan(tool)
        if self._direct_reachable(tool, base_plan):
            base_plan.note = "directly reachable (input does not depend on other tools, no sequence construction needed)"
            self.reporter.emit("plan.direct", level="debug", tool=tool.name)
            return base_plan
        self.reporter.emit("plan.needs_sequence", level="debug", tool=tool.name)
        return None

    def _explore_and_attack_sync(self, tool, sink_params, idx, total, timeout, poll_window, agent_cache):
        """Live-session path (run on the persistent agent loop): explore + attack on one session.

        On a genuine failure (session establishment / mid-flight error) discard the possibly-dirty shared loop so
        it does not pollute later tools, and record the tool as not-tested — but a budget/timeout interrupt (bare
        or wrapped by anyio into a group) and an all-models-down signal must propagate to their own handlers."""
        try:
            return self._agent_run(self._explore_and_attack(
                tool, sink_params, idx, total, timeout, poll_window, agent_cache))
        except (AllModelsUnavailable, ToolBudgetExceeded):
            raise
        except BaseException as e:   # noqa: BLE001
            if isinstance(e, BaseExceptionGroup):
                budget_exc, _rest = e.split(ToolBudgetExceeded)
                if budget_exc is not None:
                    raise
                amu, _rest2 = e.split(AllModelsUnavailable)
                if amu is not None:
                    raise
            _reset_agent_loop_after_abort()   # the shared loop may be half-stopped; rebuild for the next tool
            note = f"live session/exploration error: {str(e)[:150]}"
            self.reporter.emit("attack.tool.error", tool=tool.name, error=note)
            return [Finding(tool.name, ps.param_path, _repr_class(ps), SKIPPED, note=note)
                    for ps in sink_params]

    async def _explore_and_attack(self, tool, sink_params, idx, total, timeout, poll_window, agent_cache):
        """Open ONE session, make the target callable on it (cached recipe replay, or agent exploration that
        builds live state), then attack on that same session. When the agent built the state here, live=True tells
        run_tool not to replay prerequisites (state is already present); a cached recipe (state not built on this
        fresh session) is replayed as before (live=False)."""
        from langchain_mcp_adapters.tools import load_mcp_tools
        cf = agent._cache_file(agent_cache, self.catalog.server_name, tool.name)
        async with open_session(self.url, self.headers, timeout=timeout) as session:
            live = True
            if cf and cf.exists():
                plan = agent._plan_from_dict(json.loads(cf.read_text()))
                self.reporter.emit("agent.cache_hit", level="debug", tool=tool.name)
                live = False   # cached recipe: prerequisites not executed on this session -> replay them
            else:
                try:
                    tools = await load_mcp_tools(session)
                    plan = await agent.explore_on_session(session, tools, tool, self.settings, self.reporter)
                except AllModelsUnavailable:
                    raise   # all models down: do not degrade, bubble up so the batch layer pauses
                except Exception as e:
                    self.reporter.emit("agent.error", level="debug", tool=tool.name, error=str(e)[:200])
                    plan = planner.fallback_plan(tool)   # attack the target directly on the live session
                if cf and not plan.note.startswith("fallback"):
                    try:
                        cf.write_text(json.dumps(agent._plan_to_dict(plan), ensure_ascii=False))
                    except Exception:
                        pass
            self.reporter.emit("attack.plan", tool=tool.name, index=idx, total=total,
                               steps=len(plan.steps), reachable=plan.reachable, note=plan.note,
                               param_count=len(sink_params))
            liveness, read_back = self._make_helpers(session, tool)
            return await run_tool(session, plan, sink_params, self.synth, self.oracle,
                                  poll_window=poll_window, reporter=self.reporter, settings=self.settings,
                                  liveness=liveness, read_back=read_back, live=live)

    def _direct_reachable(self, tool, base_plan) -> bool:
        """Call the target tool once directly with base_plan's schema/benign arguments: non-error means it is
        independently reachable (no prerequisite needed).

        Sends one benign call (no payload) via our own driver. The driver creates/closes its own connection per
        call and does not cache across event loops, so using asyncio.run with an independent loop here is safe
        (unrelated to the agent's "Event loop is closed").
        """
        last = base_plan.steps[-1]
        args = {k: v.get("value") for k, v in (last.args or {}).items() if isinstance(v, dict)}
        timeout = self.settings.timeout if self.settings else None
        try:
            res = asyncio.run(self._probe_call(tool.name, args, timeout))
        except Exception:
            return False   # connection/transport failure -> conservatively treat as "needs further handling", hand to the agent
        return not res.get("is_error", True)

    async def _probe_call(self, tool_name, args, timeout):
        async with open_session(self.url, self.headers, timeout=timeout) as session:
            return await call_on(session, tool_name, args)

    def _agent_run(self, coro):
        """Run the agent coroutine on the **process-level persistent** event loop (see the _AGENT_LOOP note at the top of the module, fixes P7)."""
        loop = _get_agent_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(coro)
        finally:
            asyncio.set_event_loop(None)   # hand back a clean state, so the attack phase's asyncio.run is unaffected

    def close(self):
        """Called after each server is scanned. Does **not** close the process-level persistent agent event loop
        (shared across servers, see the top of the module) — closing it per server was exactly the root cause of
        P7 "Event loop is closed". The loop is reclaimed automatically when the process exits."""
        return

    def _attack_tool(self, tool, plan, sink_params, timeout, poll_window, retries) -> list:
        """Replay the given plan and verdict each parameter over multiple channels. Each attempt uses an
        independent event loop, isolating any anyio/event-loop corruption left over from the previous tool.
        On session-establishment failure, reconnect per retries; after all fail, do a liveness probe and
        honestly mark SKIPPED (not tested), not pretending "unreached / no vulnerability".
        """
        last_err = None
        for attempt in range(1, retries + 1):
            try:
                return asyncio.run(self._attack_once(tool, plan, sink_params, timeout, poll_window))
            except Exception as e:                      # only the session-establishment phase reaches here
                last_err = e
                if attempt < retries:
                    time.sleep(1.0 * attempt)
        alive = asyncio.run(_safe_ping(self.url, self.headers, timeout))
        note = f"session error (still failing after {retries} retries): {str(last_err)[:120]}"
        if not alive:
            note += "; and the post-hoc liveness probe failed, the server may have crashed/become unresponsive (suspected DoS signal)"
        self.reporter.emit("attack.tool.error", tool=tool.name, error=note)
        return [Finding(tool.name, ps.param_path, _repr_class(ps), SKIPPED, note=note)
                for ps in sink_params]

    def _make_helpers(self, session, tool):
        """Build the (liveness, read_back) closures over a session, shared by the replay attack (_attack_once) and
        the live-session attack (_explore_and_attack)."""
        timeout = self.settings.timeout if self.settings else None

        async def liveness():
            # Liveness heartbeat: prefer reusing the current session (list_tools), do not open a concurrent
            # session. For a backend without session isolation (e.g. stdio), a concurrent second initialize while
            # the battery session is still open fails spuriously, which once caused every tool to falsely report
            # "crashed". Only open a new session to probe the server's real state when the current session is
            # unusable, and on a real failure raise (raise_on_fail) so the upper-level recheck records the reason,
            # distinguishing "the server died" from "the local session broke".
            try:
                await session.list_tools()
                return True
            except Exception:
                return await ping(self.url, self.headers, timeout, raise_on_fail=True)

        read_back = None
        if self._reader and self._reader[0] != tool.name:
            rtool, rpath, rother = self._reader

            async def read_back(path, _rt=rtool, _rp=rpath, _ro=rother):
                res = await call_on(session, _rt, {**_ro, _rp: path})
                # If the read tool itself errors (e.g. fenced off with "path escapes ALLOWED_ROOTS") -> treat as
                # "cannot read" and return empty. Only genuinely read-back content counts as canary-landing
                # evidence (fail-closed, does not parse rejection wording).
                if res.get("is_error"):
                    return ""
                return res.get("text", "")

        return liveness, read_back

    async def _attack_once(self, tool, plan, sink_params, timeout, poll_window) -> list:
        async with open_session(self.url, self.headers, timeout=timeout) as session:
            liveness, read_back = self._make_helpers(session, tool)
            return await run_tool(session, plan, sink_params, self.synth, self.oracle,
                                  poll_window=poll_window, reporter=self.reporter,
                                  settings=self.settings, liveness=liveness, read_back=read_back)


async def _safe_ping(url, headers, timeout) -> bool:
    try:
        return await ping(url, headers, timeout)
    except Exception:
        return False


def _repr_class(ps):
    cls = ps.ranked_classes() if hasattr(ps, "ranked_classes") else []
    return cls[0] if cls else "unknown"


_READ_KEYS = ("read", "cat", "show", "get", "content", "dump", "view", "open", "load")
_PATH_KEYS = ("path", "file", "filename", "filepath", "location")


def _find_reader(catalog):
    """Find a read tool in the catalog that "returns file content given a path", for cross_tool canary read-back.

    Heuristic, generic, not targeted at any server: the tool name/description contains a read-type word + it has
    one path-type string parameter; pick the one with the fewest required parameters. Returns
    (tool_name, path_param, benign_other_required_args) or None.
    """
    best = None
    for t in catalog.tools:
        hay = (t.name + " " + (t.description or "")).lower()
        if not any(k in hay for k in _READ_KEYS):
            continue
        ppath = None
        for p in t.params:
            if p.type in ("string", "union", "unknown") and any(k in p.path.lower() for k in _PATH_KEYS):
                ppath = p.path
                break
        if ppath is None:
            continue
        nreq = sum(1 for p in t.params if p.required)
        if best is None or nreq < best[0]:
            others = {p.path: planner._fallback_literal(p) for p in t.params
                      if p.required and p.path != ppath}
            best = (nreq, t.name, ppath, others)
    return (best[1], best[2], best[3]) if best else None
