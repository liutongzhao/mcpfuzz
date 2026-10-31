"""编排器门面：把前四步串成检测流水线。

对每个"有 sink 的工具"：规划(一次,缓存) → 开持久会话 → 建发射台 → 逐参数发载荷验证 → 汇总 Finding。
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path

from mcpfuzz.driver import call_on, open_session, ping
from mcpfuzz.payload import PayloadSynthesizer

from . import agent, planner
from .executor import run_tool
from .types import SKIPPED, Finding


class _NullReporter:
    def emit(self, *a, **k):
        pass


class Orchestrator:
    def __init__(self, url, headers, catalog, oracle, cache_dir: str | Path | None = None,
                reporter=None, settings=None):
        """reporter: cli.events.Reporter，不传则静默（内核仍可被当库调用）。
        settings: config.Settings，带 llm_plan/poll_rounds/poll_interval/timeout/delay/max_payloads 等旋钮。
        """
        self.url = url
        self.headers = headers
        self.catalog = catalog
        self.oracle = oracle
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.synth = PayloadSynthesizer(oracle)
        self._tools_by_name = {t.name: t for t in catalog.tools}
        self._reader = _find_reader(catalog)   # cross_tool canary 读回器（可能为 None）
        self.reporter = reporter or _NullReporter()
        self.settings = settings

    def run(self, param_sinks, only_tools=None, dry_run: bool = False) -> list:
        """param_sinks: sink.ParamSinkPrior 列表。only_tools: 限定工具名集合(调试用)。
        dry_run: 只出计划、不发任何载荷（recon 用）。返回 Finding 列表。"""
        # 保留所有非惰性、有启用类别的参数（不按单标签门控——floor 保证每类都会被测），按工具分组
        by_tool: dict[str, list] = {}
        for ps in param_sinks:
            if only_tools and ps.tool not in only_tools:
                continue
            if not getattr(ps, "inert", False) and ps.class_weights:
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
        total = len(by_tool)
        for idx, (tool_name, sink_params) in enumerate(by_tool.items(), 1):
            tool = self._tools_by_name.get(tool_name)
            if tool is None:
                continue
            if dry_run:
                # dry-run 只预览假设计划（不实跑、不走智能体），保持"未发送任何请求"的语义
                p = planner.plan(tool, self.catalog, cache_dir=plan_cache) if use_llm_plan \
                    else planner.fallback_plan(tool)
                self.reporter.emit("attack.plan", tool=tool_name, index=idx, total=total,
                                   steps=len(p.steps), reachable=p.reachable, note=p.note,
                                   param_count=len(sink_params))
                continue
            # 序列构建在攻击会话之外完成（智能体自建 MCP 连接做发现），再开会话确定性回放
            plan = self._build_plan_sync(tool, use_agent, plan_cache, agent_cache)
            self.reporter.emit("attack.plan", tool=tool_name, index=idx, total=total,
                               steps=len(plan.steps), reachable=plan.reachable, note=plan.note,
                               param_count=len(sink_params))
            findings += self._attack_tool(tool, plan, sink_params, timeout, poll_window, retries)
        return findings

    def _build_plan_sync(self, tool, use_agent, plan_cache, agent_cache):
        """序列构建：优先 LangGraph 智能体（自建连接实跑产配方）；异常/未启用回退一次性规划 / schema 兜底。"""
        if use_agent:
            try:
                return asyncio.run(agent.build_sequence(self.url, self.headers, tool, self.catalog,
                                                        self.settings, self.reporter, cache_dir=agent_cache))
            except Exception as e:
                self.reporter.emit("agent.error", level="debug", tool=tool.name, error=str(e)[:200])
        if self.settings and self.settings.llm_plan:
            return planner.plan(tool, self.catalog, cache_dir=plan_cache)
        return planner.fallback_plan(tool)

    def _attack_tool(self, tool, plan, sink_params, timeout, poll_window, retries) -> list:
        """回放给定计划并对每个参数多通道判定。每次尝试独立事件循环，隔离上一工具可能残留的
        anyio/事件循环损坏状态。会话建立失败按 retries 重连；全部失败后做存活探测，如实标
        SKIPPED（未测成），不冒充"未触达/无漏洞"。
        """
        last_err = None
        for attempt in range(1, retries + 1):
            try:
                return asyncio.run(self._attack_once(tool, plan, sink_params, timeout, poll_window))
            except Exception as e:                      # 仅会话建立阶段才会抛到这里
                last_err = e
                if attempt < retries:
                    time.sleep(1.0 * attempt)
        alive = asyncio.run(_safe_ping(self.url, self.headers, timeout))
        note = f"会话异常（重试 {retries} 次仍失败）：{str(last_err)[:120]}"
        if not alive:
            note += "；且事后存活探测失败，服务器可能已崩溃/无响应（疑似 DoS 信号）"
        self.reporter.emit("attack.tool.error", tool=tool.name, error=note)
        return [Finding(tool.name, ps.param_path, _repr_class(ps), SKIPPED, note=note)
                for ps in sink_params]

    async def _attack_once(self, tool, plan, sink_params, timeout, poll_window) -> list:
        async with open_session(self.url, self.headers, timeout=timeout) as session:
            async def liveness():
                return await ping(self.url, self.headers, timeout)

            read_back = None
            if self._reader and self._reader[0] != tool.name:
                rtool, rpath, rother = self._reader

                async def read_back(path, _rt=rtool, _rp=rpath, _ro=rother):
                    res = await call_on(session, _rt, {**_ro, _rp: path})
                    return res.get("text", "")

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
    """在工具目录里找一个'给路径返回文件内容'的读工具，供 cross_tool canary 读回。

    启发式、通用、不针对任何服务器：工具名/描述含读取类词 + 有一个路径型字符串参数，
    取必填参数最少者。返回 (tool_name, path_param, benign_other_required_args) 或 None。
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
