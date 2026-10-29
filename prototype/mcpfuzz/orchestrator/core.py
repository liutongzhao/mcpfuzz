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


class Orchestrator:
    def __init__(self, url, headers, catalog, oracle, cache_dir: str | Path | None = None):
        self.url = url
        self.headers = headers
        self.catalog = catalog
        self.oracle = oracle
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.synth = PayloadSynthesizer(oracle)
        self._tools_by_name = {t.name: t for t in catalog.tools}

    def run(self, param_sinks, only_tools=None) -> list:
        """param_sinks: sink.ParamSink 列表。only_tools: 限定工具名集合(调试用)。返回 Finding 列表。"""
        # 只保留第一期能出载荷的 sink，并按工具分组
        by_tool: dict[str, list] = {}
        for ps in param_sinks:
            if only_tools and ps.tool not in only_tools:
                continue
            if any(s.type in PHASE1_SINKS for s in ps.sinks):
                by_tool.setdefault(ps.tool, []).append(ps)
        return asyncio.run(self._run_all(by_tool))

    async def _run_all(self, by_tool) -> list:
        findings = []
        plan_cache = self.cache_dir / ".plan_cache" if self.cache_dir else None
        for tool_name, sink_params in by_tool.items():
            tool = self._tools_by_name.get(tool_name)
            if tool is None:
                continue
            p = planner.plan(tool, self.catalog, cache_dir=plan_cache)   # 同步 LLM，会话外做
            print(f"[编排] {tool_name}: 计划 {len(p.steps)} 步, {len(sink_params)} 个参数待测", flush=True)
            try:
                async with open_session(self.url, self.headers) as session:
                    findings += await run_tool(session, p, sink_params, self.synth, self.oracle)
            except Exception as e:
                print(f"[编排] {tool_name} 会话异常: {str(e)[:120]}", flush=True)
        return findings
