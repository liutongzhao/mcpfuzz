"""编排器门面：把前四步串成检测流水线。

对每个"有 sink 的工具"：规划(一次,缓存) → 开持久会话 → 建发射台 → 逐参数发载荷验证 → 汇总 Finding。
"""
from __future__ import annotations

import asyncio
import signal
import time
from pathlib import Path

from mcpfuzz.driver import call_on, open_session, ping
from mcpfuzz.llm_failover import AllModelsUnavailable
from mcpfuzz.payload import PayloadSynthesizer

from . import agent, planner
from .executor import run_tool
from .types import SKIPPED, Finding, Plan

# 智能体探索的事件循环：**进程级常驻**（跨所有服务/Orchestrator 共用一个）。
# 为什么不能每服务新建/关闭：LangGraph 的 LLM 异步客户端(ChatOpenAI/httpx)把底层连接缓存在首次
# 使用的事件循环上；若每个服务换新循环、扫完就关，下一个服务首个 agent 调用复用到的缓存客户端仍
# 绑在已关闭的旧循环上 → "Event loop is closed"，致每个服务的第一个多步工具序列构建崩溃（P7）。
# 进程级常驻一个循环即根治（攻击阶段用各自独立的 asyncio.run 临时循环，互不影响）。
# 假设：批扫是**串行**的（cli 对目标逐个循环），任一时刻只有一个 _agent_run 在跑。若将来并行化
# 或在多线程宿主里并发使用，需换成每线程循环或加重入保护，否则会 "event loop is already running"。
_AGENT_LOOP = None


def _get_agent_loop():
    global _AGENT_LOOP
    if _AGENT_LOOP is None or _AGENT_LOOP.is_closed():
        _AGENT_LOOP = asyncio.new_event_loop()
    return _AGENT_LOOP


# --- 单工具总时长看门狗 ------------------------------------------------------
# 用 SIGALRM 在主线程上硬性限时：一个工具（序列构建 + 攻击判定）耗时超预算就抛出中断，
# 放弃该工具、换下一个，避免某个工具把整批卡死。只在 Unix 主线程生效（容器内即是）；
# 装不上就优雅退化为"无单工具超时"，不影响检测本身。


class ToolBudgetExceeded(BaseException):
    """单工具超预算中断。**刻意继承 BaseException**（而非 Exception）：这样 _build_plan_sync /
    _attack_tool 里那些 `except Exception` 不会把它吞掉，能一路冒泡到工具循环层被专门处理。"""


def _raise_tool_budget(signum, frame):
    raise ToolBudgetExceeded()


def _arm_tool_alarm(seconds: float) -> bool:
    """装一个 seconds 秒后触发的 SIGALRM 看门狗；返回是否真的装上了。
    预算 <=0 / 非 Unix / 非主线程（signal.signal 会抛 ValueError）→ 返回 False，退化为无看门狗。"""
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
    """工具超时被中断后调用。智能体常驻事件循环可能停在半截的 await 上（有悬挂任务/半开 socket）；
    保守起见整只丢弃并重置绑在其上的 ChatOpenAI 单例，下一个工具用全新循环+客户端重建，
    避免残留任务或 'Event loop is closed' 污染后续工具。只有真超时才付这点重建代价（极少发生）。"""
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
        tool_budget = float(getattr(self.settings, "tool_timeout", 0.0) or 0.0) if self.settings else 0.0
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
            # 单工具总时长看门狗：序列构建+攻击判定合起来超预算就放弃本工具、记未测成、换下一个，
            # 避免某个工具（最常见是智能体序列构建啃不动的依赖链）把整批卡死。
            t_tool = time.time()
            armed = _arm_tool_alarm(tool_budget)
            try:
                # 序列构建在攻击会话之外完成（智能体自建 MCP 连接做发现），再开会话确定性回放
                plan = self._build_plan_sync(tool, use_agent, plan_cache, agent_cache)
                self.reporter.emit("attack.plan", tool=tool_name, index=idx, total=total,
                                   steps=len(plan.steps), reachable=plan.reachable, note=plan.note,
                                   param_count=len(sink_params))
                findings += self._attack_tool(tool, plan, sink_params, timeout, poll_window, retries)
            except ToolBudgetExceeded:
                findings += self._on_tool_timeout(tool_name, idx, total, t_tool, tool_budget, sink_params)
            except BaseException as e:   # noqa: BLE001
                # 看门狗中断若在 MCP/anyio 会话(async with open_session)里触发，anyio 清理子任务时会把它
                # 包进 BaseExceptionGroup —— 裸 `except ToolBudgetExceeded` 接不住“装着它的盒子”，会漏到
                # 进程层崩掉 runner。这里拆盒子：组里只要含看门狗中断就按“单工具超时”同样收尾、继续下一个；
                # 不含（真·错误 / KeyboardInterrupt 等）则原样抛出，绝不吞。
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
        """单工具超时的统一收尾：报事件、丢弃智能体残留事件循环、把该工具所有参数记 SKIPPED（未测成）。
        看门狗中断无论是裸抛的 ToolBudgetExceeded，还是被 anyio 包成的 BaseExceptionGroup，都走这里。"""
        elapsed = time.time() - t_tool
        note = f"单工具超时（预算 {int(tool_budget)}s，用时 {elapsed:.0f}s）已放弃，换下一个工具"
        self.reporter.emit("attack.tool.timeout", tool=tool_name, index=idx, total=total,
                           seconds=round(elapsed, 1), budget=tool_budget)
        _reset_agent_loop_after_abort()   # 智能体常驻循环可能停在半截，丢弃重建免污染后续工具
        return [Finding(tool_name, ps.param_path, _repr_class(ps), SKIPPED, note=note)
                for ps in sink_params]

    def _build_plan_sync(self, tool, use_agent, plan_cache, agent_cache):
        """序列构建。先判"是否需要前置"：用良性值直接试调一次目标工具——
        **调通即为独立工具，用单步计划、不惊动智能体/一次性规划**；调不通才去建序列。
        这是最可靠的通用判据（不静态猜依赖、不针对任何服务器），且顺带产出"需序列构建的工具占比"指标。
        """
        want_llm_plan = self.settings is None or self.settings.llm_plan
        if want_llm_plan:
            base_plan = planner.fallback_plan(tool)
            if self._direct_reachable(tool, base_plan):
                base_plan.note = "直连可达（输入不依赖其它工具，无需序列构建）"
                self.reporter.emit("plan.direct", level="debug", tool=tool.name)
                return base_plan
            self.reporter.emit("plan.needs_sequence", level="debug", tool=tool.name)

        if use_agent:
            try:
                return self._agent_run(agent.build_sequence(
                    self.url, self.headers, tool, self.catalog, self.settings,
                    self.reporter, cache_dir=agent_cache))
            except AllModelsUnavailable:
                raise   # 所有模型都挂了：冒泡到批量层暂停，不再退而求其次
            except Exception as e:
                self.reporter.emit("agent.error", level="debug", tool=tool.name, error=str(e)[:200])
        if want_llm_plan:
            return planner.plan(tool, self.catalog, cache_dir=plan_cache)
        return planner.fallback_plan(tool)

    def _direct_reachable(self, tool, base_plan) -> bool:
        """用 base_plan 的 schema/良性实参直接调一次目标工具：非报错即独立可达（无需前置）。

        用我方 driver 发一次良性调用（不含载荷）。驱动每次调用新建/关闭自己的连接、不跨事件循环
        缓存，故这里用 asyncio.run 独立事件循环是安全的（与智能体那个"Event loop is closed"无关）。
        """
        last = base_plan.steps[-1]
        args = {k: v.get("value") for k, v in (last.args or {}).items() if isinstance(v, dict)}
        timeout = self.settings.timeout if self.settings else None
        try:
            res = asyncio.run(self._probe_call(tool.name, args, timeout))
        except Exception:
            return False   # 连接/传输失败 → 保守地当作"需要进一步处理"，交给智能体
        return not res.get("is_error", True)

    async def _probe_call(self, tool_name, args, timeout):
        async with open_session(self.url, self.headers, timeout=timeout) as session:
            return await call_on(session, tool_name, args)

    def _agent_run(self, coro):
        """在**进程级常驻**事件循环上跑智能体协程（见模块顶部 _AGENT_LOOP 说明，根治 P7）。"""
        loop = _get_agent_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(coro)
        finally:
            asyncio.set_event_loop(None)   # 交回干净状态，后续攻击阶段的 asyncio.run 不受影响

    def close(self):
        """每服务扫完调用。**不**关闭进程级常驻的智能体事件循环（跨服务共用一个，见模块顶部）——
        此前每服务关闭该循环，正是 P7 "Event loop is closed" 的根因。循环随进程退出自动回收。"""
        return

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
                # 存活心跳：优先复用当前会话(list_tools)，不新开并发会话。对 stdio 等无会话
                # 隔离的后端，battery 会话还开着时并发第二个 initialize 会假失败，曾导致每个
                # 工具都误报"崩溃"。仅当前会话不可用时才新开会话探服务器真实状态，真失败则
                # 抛出(raise_on_fail)交由上层 recheck 记录原因，用以区分"服务器挂了"与"本地会话坏了"。
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
                    # 读工具本身报错（如被围栏拒绝 "path escapes ALLOWED_ROOTS"）→ 视为“读不到”，
                    # 返回空。只有真正成功读回的正文才算 canary 落地证据（fail-closed，不解析错误措辞）。
                    if res.get("is_error"):
                        return ""
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
