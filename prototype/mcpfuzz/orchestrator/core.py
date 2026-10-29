"""编排器门面：把前四步串成检测流水线。

对每个"有 sink 的工具"：规划(一次,缓存) → 开持久会话 → 建发射台 → 逐参数发载荷验证 → 汇总 Finding。
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from mcpfuzz.driver import open_session
from mcpfuzz.payload import PHASE1_SINKS, PayloadSynthesizer

from . import planner
from .executor import run_tool
from .types import UNREACHED, Finding


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
        return asyncio.run(self._run_all(by_tool, dry_run))

    async def _run_all(self, by_tool, dry_run) -> list:
        findings = []
        plan_cache = self.cache_dir / ".plan_cache" if self.cache_dir else None
        use_llm_plan = self.settings.llm_plan if self.settings else True
        timeout = self.settings.timeout if self.settings else None
        poll_window = (self.settings.poll_rounds, self.settings.poll_interval) if self.settings else (3, 2.0)
        total = len(by_tool)
        for idx, (tool_name, sink_params) in enumerate(by_tool.items(), 1):
            tool = self._tools_by_name.get(tool_name)
            if tool is None:
                continue
            if use_llm_plan:
                p = planner.plan(tool, self.catalog, cache_dir=plan_cache)   # 同步 LLM，会话外做
            else:
                p = planner.fallback_plan(tool)
            self.reporter.emit("attack.plan", tool=tool_name, index=idx, total=total,
                               steps=len(p.steps), reachable=p.reachable, note=p.note,
                               param_count=len(sink_params))
            if dry_run:
                continue
            try:
                async with open_session(self.url, self.headers, timeout=timeout) as session:
                    findings += await run_tool(session, p, sink_params, self.synth, self.oracle,
                                               poll_window=poll_window, reporter=self.reporter,
                                               settings=self.settings)
            except Exception as e:
                self.reporter.emit("attack.tool.error", tool=tool_name, error=str(e)[:200])
                findings += [Finding(tool_name, ps.param_path, _sink_of(ps), UNREACHED,
                                     note=f"会话异常: {str(e)[:120]}") for ps in sink_params]
        return findings


def _sink_of(ps):
    return ps.sinks[0].type if ps.sinks else "unknown"
