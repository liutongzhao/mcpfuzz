"""编排器门面：把前四步串成检测流水线。

对每个"有 sink 的工具"：规划(一次,缓存) → 开持久会话 → 建发射台 → 逐参数发载荷验证 → 汇总 Finding。
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path

from mcpfuzz.driver import open_session, ping
from mcpfuzz.payload import PHASE1_SINKS, PayloadSynthesizer

from . import planner
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
        self.reporter = reporter or _NullReporter()
        self.settings = settings

    def run(self, param_sinks, only_tools=None, dry_run: bool = False) -> list:
        """param_sinks: sink.ParamSink 列表。only_tools: 限定工具名集合(调试用)。
        dry_run: 只出计划、不发任何载荷（recon 用）。返回 Finding 列表。"""
        # 只保留第一期能出载荷的 sink，并按工具分组
        by_tool: dict[str, list] = {}
        for ps in param_sinks:
            if only_tools and ps.tool not in only_tools:
                continue
            if any(s.type in PHASE1_SINKS for s in ps.sinks):
                by_tool.setdefault(ps.tool, []).append(ps)
        return self._run_all(by_tool, dry_run)

    def _run_all(self, by_tool, dry_run) -> list:
        findings = []
        plan_cache = self.cache_dir / ".plan_cache" if self.cache_dir else None
        use_llm_plan = self.settings.llm_plan if self.settings else True
        timeout = self.settings.timeout if self.settings else None
        retries = max(1, self.settings.retries) if self.settings else 3
        poll_window = (self.settings.poll_rounds, self.settings.poll_interval) if self.settings else (3, 2.0)
        total = len(by_tool)
        for idx, (tool_name, sink_params) in enumerate(by_tool.items(), 1):
            tool = self._tools_by_name.get(tool_name)
            if tool is None:
                continue
            if use_llm_plan:
                p = planner.plan(tool, self.catalog, cache_dir=plan_cache)
            else:
                p = planner.fallback_plan(tool)
            self.reporter.emit("attack.plan", tool=tool_name, index=idx, total=total,
                               steps=len(p.steps), reachable=p.reachable, note=p.note,
                               param_count=len(sink_params))
            if dry_run:
                continue
            findings += self._attack_tool(tool_name, p, sink_params, timeout, poll_window, retries)
        return findings

    def _attack_tool(self, tool_name, p, sink_params, timeout, poll_window, retries) -> list:
        """对单个工具发起攻击。每次尝试用独立事件循环，彻底隔离上一工具可能残留的
        anyio/事件循环损坏状态——这是之前一次会话崩溃后、后续所有工具都级联报
        `generator didn't yield` 的根因。会话建立失败按 retries 重连重试；全部失败后
        做一次存活探测，把结果如实标为 SKIPPED（未能测试），而非冒充"未触达/无漏洞"。
        """
        last_err = None
        for attempt in range(1, retries + 1):
            try:
                return asyncio.run(self._attack_once(p, sink_params, timeout, poll_window))
            except Exception as e:                      # 仅会话建立阶段才会抛到这里
                last_err = e
                if attempt < retries:
                    time.sleep(1.0 * attempt)
        alive = asyncio.run(_safe_ping(self.url, self.headers, timeout))
        note = f"会话异常（重试 {retries} 次仍失败）：{str(last_err)[:120]}"
        if not alive:
            note += "；且事后存活探测失败，服务器可能已崩溃/无响应（疑似 DoS 信号）"
        self.reporter.emit("attack.tool.error", tool=tool_name, error=note)
        return [Finding(tool_name, ps.param_path, _sink_of(ps), SKIPPED, note=note)
                for ps in sink_params]

    async def _attack_once(self, p, sink_params, timeout, poll_window) -> list:
        async with open_session(self.url, self.headers, timeout=timeout) as session:
            return await run_tool(session, p, sink_params, self.synth, self.oracle,
                                  poll_window=poll_window, reporter=self.reporter,
                                  settings=self.settings)


async def _safe_ping(url, headers, timeout) -> bool:
    try:
        return await ping(url, headers, timeout)
    except Exception:
        return False


def _sink_of(ps):
    return ps.sinks[0].type if ps.sinks else "unknown"
