"""终端呈现层：把事件流渲染成实时界面（rich）或纯文本/JSON（降级），供 Reporter 挂载。

三种呈现由 --format 选择，默认 auto：TTY 用 rich 的 Live 实时界面，非 TTY（管道/重定向/CI）
自动降级为逐行 plain 文本。json 则把事件原样一行一行吐给 stdout，供外部程序消费。
各呈现类都实现 start(label) / handle(event)（可直接当 Reporter 的 sink）/ stop() -> 摘要。
"""
from __future__ import annotations

import sys
import time
from collections import deque
from datetime import datetime

from .events import Event

_LOG_HEIGHT = 16
_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


class _Dynamic:
    """让 rich.Live 每次刷新都重新渲染：Live 以固定帧率调用 __rich__，于是计时器实时
    跳动、spinner 持续转动，而不是停在"上一条事件发生的那一刻"。没有它，Live 只会反复
    重贴同一张静态快照——这正是之前"时间不走、长等待像卡死"的原因。"""

    def __init__(self, fn):
        self._fn = fn

    def __rich__(self):
        return self._fn()


def build_console(fmt: str, verbose: int = 0, quiet: bool = False):
    """按 --format（auto/rich/plain/json）挑一个呈现实现。"""
    if fmt == "json":
        return JsonConsole()
    if fmt == "auto":
        fmt = "rich" if sys.stdout.isatty() else "plain"
    if fmt == "rich":
        try:
            return RichConsole(verbose=verbose, quiet=quiet)
        except Exception:
            return PlainConsole(verbose=verbose, quiet=quiet)   # 环境缺 rich 时兜底
    return PlainConsole(verbose=verbose, quiet=quiet)


class JsonConsole:
    """逐行把事件原样吐到 stdout（机读）。"""

    def start(self, label: str) -> None:
        pass

    def handle(self, ev: Event) -> None:
        print(ev.to_json(), flush=True)

    def stop(self) -> None:
        pass


class _BaseTextConsole:
    """plain / rich 共用的状态跟踪：阶段、计数、确认漏洞列表。"""

    def __init__(self, verbose: int = 0, quiet: bool = False):
        self.verbose = verbose
        self.quiet = quiet
        self._reset("")

    def _reset(self, label: str) -> None:
        """批量扫描时 console 实例跨目标复用，每个目标开始前必须清空上一个的状态。"""
        self.label = label
        self.stage = "connect"
        self.tool_index = 0
        self.tool_total = 0
        self.cur_tool = ""
        self.sink_done = 0
        self.sink_total = 0
        self.cur_activity = ""      # 当前正在做的细节（供实时界面显示，证明还在跑）
        self.counts = {"confirmed": 0, "clean": 0, "unreached": 0, "skipped": 0}
        self.confirmed_findings: list[dict] = []
        self.dry_run = False

    def _update(self, ev: Event) -> None:
        d = ev.data
        if ev.type == "connect.ok":
            name = f"{d.get('server_name') or '?'} {d.get('server_version') or ''}".strip()
            self.label = f"{self.label}  [{name}]" if self.label else name
        elif ev.type == "sink.start":
            self.stage = "sink"
            self.sink_total = d.get("tool_count", 0)
            self.sink_done = 0
            self.cur_activity = "调用大模型识别 sink …"
        elif ev.type == "sink.progress":
            self.sink_done = d.get("done", self.sink_done)
            self.sink_total = d.get("total", self.sink_total)
            self.cur_activity = f"已识别工具 {d.get('tool', '')}"
        elif ev.type == "sink.done":
            self.cur_activity = ""
        elif ev.type == "attack.plan":
            self.stage = "attack"
            self.cur_tool = d.get("tool", "")
            self.tool_index = d.get("index", self.tool_index)
            self.tool_total = d.get("total", self.tool_total)
            self.cur_activity = f"规划 {d.get('tool', '')} 的调用序列 …"
        elif ev.type == "attack.param.start":
            self.cur_activity = f"发射载荷 {d.get('tool', '')}.{d.get('param', '')}（{d.get('payload_count', '?')} 条，{d.get('sink', '')}）"
        elif ev.type == "finding.confirmed":
            self.counts["confirmed"] += 1
            self.confirmed_findings.append(d)
        elif ev.type == "finding.clean":
            self.counts["clean"] += 1
        elif ev.type == "finding.unreached":
            self.counts["unreached"] += 1
        elif ev.type == "finding.skipped":
            self.counts["skipped"] += 1
        elif ev.type == "run.end":
            self.stage = "done"
            self.dry_run = bool(d.get("dry_run"))


STAGE_LABELS = {"connect": "连接", "sink": "Sink 推断", "attack": "攻击编排", "done": "完成"}


def _fmt_line(ev: Event) -> str | None:
    """把一个事件格式化成一行人读文本；返回 None 表示该事件不值得单独一行（极少噪音）。"""
    d, t = ev.data, ev.type
    if t == "run.start":
        return f"开始扫描 {d.get('url')} → {d.get('run_dir')}"
    if t == "connect.ok":
        return (f"连接成功  {d.get('server_name') or '?'} {d.get('server_version') or ''}  "
                f"协议 {d.get('protocol_version')}  工具数 {d.get('tool_count')}")
    if t == "connect.fail":
        return f"连接失败  {d.get('error')}"
    if t == "sink.start":
        return f"推断 sink …（{d.get('tool_count')} 个工具）"
    if t == "sink.progress":
        return f"  sink 进度 {d.get('done')}/{d.get('total')}  （{d.get('tool')}）"
    if t == "sink.labeled":
        tags = ",".join(f"{s['type']}({s['confidence']}/{s['source']})" for s in d.get("sinks", []))
        return f"[sink] {d.get('tool')}.{d.get('param')} → {tags}"
    if t == "sink.done":
        return f"sink 推断完成  有候选 {d.get('hot_count')}/{d.get('param_count')} 个参数"
    if t == "attack.plan":
        note = f"  ({d.get('note')})" if d.get("note") else ""
        reach = "" if d.get("reachable", True) else "  [不可达]"
        return (f"[plan] ({d.get('index')}/{d.get('total')}) {d.get('tool')}: "
                f"{d.get('steps')} 步, {d.get('param_count')} 个参数待测{reach}{note}")
    if t == "attack.tool.error":
        return f"[异常] {d.get('tool')} 会话异常: {d.get('error')}"
    if t == "launchpad.fail":
        return f"[未测成] {d.get('tool')}: {d.get('reason')}"
    if t == "launchpad.warn":
        return f"[前置不全] {d.get('tool')}: {d.get('reason')}（仍继续测试目标工具）"
    if t == "attack.param.start":
        return f"[attack] {d.get('tool')}.{d.get('param')} ← 发射 {d.get('payload_count')} 条载荷 ({d.get('sink')})"
    if t == "payload.sent":
        flag = "✗" if d.get("is_error") else "✓"
        return f"  载荷 {flag} [{d.get('channel')}] {d.get('payload')!r}"
    if t == "finding.confirmed":
        return (f"● 确认  {d.get('tool')}.{d.get('param')}  ({d.get('sink')}, 通道 {d.get('channel')})\n"
                f"    载荷: {d.get('payload')!r}\n"
                f"    证据: {d.get('evidence')}")
    if t == "finding.clean":
        return f"○ 疑似无漏洞  {d.get('tool')}.{d.get('param')}  ({d.get('sink')})"
    if t == "finding.unreached":
        note = f"  ({d.get('note')})" if d.get("note") else ""
        return f"○ 未触达  {d.get('tool')}.{d.get('param')}  ({d.get('sink')}){note}"
    if t == "finding.skipped":
        note = f"  ({d.get('note')})" if d.get("note") else ""
        return f"⊘ 未测成  {d.get('tool')}.{d.get('param')}  ({d.get('sink')}){note}"
    if t == "report.saved":
        return f"报告已保存：{d.get('path')}"
    if t == "run.end":
        if d.get("dry_run"):
            return "（dry-run，未发送任何载荷）"
        return (f"结束  用时 {d.get('duration', 0):.1f}s  "
                f"确认 {d.get('confirmed')} | 疑似无 {d.get('clean')} | 未触达 {d.get('unreached')} | "
                f"未测成 {d.get('skipped', 0)} | 总计 {d.get('total')}")
    return None


class PlainConsole(_BaseTextConsole):
    """非 TTY / --format plain：逐行带时间戳输出，无重绘，适合管道与 CI。"""

    def start(self, label: str) -> None:
        self._reset(label)
        print(f"=== MCPFuzz ▸ {label} ===", flush=True)

    def handle(self, ev: Event) -> None:
        if ev.level == "debug" and self.verbose < 2:
            return
        self._update(ev)
        if self.quiet and ev.type not in ("finding.confirmed", "connect.fail", "run.end", "report.saved"):
            return
        line = _fmt_line(ev)
        if line is None:
            return
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"{ts}  {line}", flush=True)

    def stop(self) -> None:
        pass


class RichConsole(_BaseTextConsole):
    """TTY 默认：rich Live 实时界面——顶部状态 + 下方滚动日志；确认漏洞红色醒目。"""

    def __init__(self, verbose: int = 0, quiet: bool = False):
        super().__init__(verbose, quiet)
        from rich.console import Console as _RC
        from rich.live import Live
        self._Live = Live
        self.console = _RC()
        self.log_lines: deque = deque(maxlen=_LOG_HEIGHT)
        self._live = None
        self._t0 = time.time()

    def start(self, label: str) -> None:
        self._reset(label)
        self.log_lines.clear()
        self._t0 = time.time()
        # 传入动态渲染对象 + 较高帧率：Live 自动按帧刷新，计时器/spinner 实时动。
        self._live = self._Live(_Dynamic(self._render), console=self.console,
                                refresh_per_second=12, transient=False)
        self._live.start()

    def handle(self, ev: Event) -> None:
        if ev.level == "debug" and self.verbose < 2:
            return
        self._update(ev)
        # sink.progress 只反映在顶部状态条，不逐条刷进滚动日志（否则一堆噪音行）
        if ev.type != "sink.progress":
            line = _fmt_line(ev)
            if line is not None:
                self._append(ev, line)
        # 渲染交给 Live 的自动刷新（_Dynamic），无需在此手动 update

    def stop(self) -> None:
        if self._live:
            self._live.stop()
        self._print_summary()

    # ---------- 内部 ----------

    def _append(self, ev: Event, line: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        style = None
        if ev.type == "finding.confirmed":
            style = "bold red"
        elif ev.type in ("connect.fail", "attack.tool.error"):
            style = "red"
        elif ev.type in ("launchpad.fail", "launchpad.warn", "finding.unreached", "finding.skipped"):
            style = "yellow"
        elif ev.type == "finding.clean":
            style = "green"
        self.log_lines.append((ts, line, style))

    def _render(self):
        from rich.console import Group
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        header = Table.grid(padding=(0, 2))
        header.add_column()
        header.add_column()
        header.add_row("目标", self.label or "-")
        done = self.stage == "done"
        spin = "✓" if done else _SPINNER[int((time.time() - self._t0) * 12) % len(_SPINNER)]
        stage_line = f"{spin} {STAGE_LABELS.get(self.stage, self.stage)}"
        if self.stage == "sink" and self.sink_total:
            stage_line += f"  [{self.sink_done}/{self.sink_total} 工具]"
        elif self.stage == "attack" and self.tool_total:
            stage_line += f"  [{self.tool_index}/{self.tool_total}]  当前: {self.cur_tool}"
        header.add_row("阶段", stage_line)
        if self.cur_activity and not done:
            header.add_row("正在", f"{self.cur_activity}")
        header.add_row("结果", f"● 确认 {self.counts['confirmed']}   "
                               f"疑似无 {self.counts['clean']}   未触达 {self.counts['unreached']}   "
                               f"未测成 {self.counts['skipped']}")
        elapsed = int(time.time() - self._t0)
        header.add_row("用时", f"{elapsed // 60}:{elapsed % 60:02d}" if elapsed >= 60 else f"{elapsed}s")

        body = Text()
        for ts, line, style in list(self.log_lines):   # 快照：Live 在后台线程渲染，避免迭代中被改
            body.append(f"{ts}  ", style="dim")
            body.append(line + "\n", style=style)

        return Group(
            Panel(header, title="MCPFuzz", border_style="cyan"),
            Panel(body, title="实时日志", border_style="grey50", height=_LOG_HEIGHT + 2),
        )

    def _print_summary(self) -> None:
        from rich.table import Table
        if self.dry_run:
            self.console.print("[dim]dry-run：仅预览攻击面，未发送任何载荷。[/dim]")
            return
        table = Table(title=f"检测结论 — {self.label}")
        table.add_column("状态")
        table.add_column("数量", justify="right")
        table.add_row("[bold red]确认漏洞[/bold red]", str(self.counts["confirmed"]))
        table.add_row("疑似无漏洞", str(self.counts["clean"]))
        table.add_row("未触达", str(self.counts["unreached"]))
        table.add_row("未测成", str(self.counts["skipped"]))
        self.console.print(table)
        for f in self.confirmed_findings:
            self.console.print(f"  [bold red]●[/bold red] {f.get('tool')}.{f.get('param')}  "
                               f"({f.get('sink')}, 通道 {f.get('channel')})  载荷: {f.get('payload')!r}")
