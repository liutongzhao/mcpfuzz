"""Terminal presentation layer: render the event stream into a live UI (rich) or plain text/JSON (degraded), to be attached to a Reporter.

Three presentations are chosen by --format, default auto: a TTY uses rich's Live UI, a non-TTY (pipe/redirect/CI)
auto-degrades to line-by-line plain text. json dumps events verbatim one per line to stdout, for an external
program to consume. Each presentation class implements start(label) / handle(event) (usable directly as a
Reporter sink) / stop() -> summary.
"""
from __future__ import annotations

import sys
import time
from collections import deque
from datetime import datetime

from calchas.__about__ import APP_NAME
from .events import Event

_LOG_HEIGHT = 16
_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


class _Dynamic:
    """Make rich.Live re-render on every refresh: Live calls __rich__ at a fixed frame rate, so the timer ticks
    live and the spinner keeps turning, instead of being frozen at "the moment the last event happened". Without
    it, Live would just repaint the same static snapshot — which was exactly why "the time did not move, a long
    wait looked frozen"."""

    def __init__(self, fn):
        self._fn = fn

    def __rich__(self):
        return self._fn()


def build_console(fmt: str, verbose: int = 0, quiet: bool = False):
    """Pick a presentation implementation by --format (auto/rich/plain/json)."""
    if fmt == "json":
        return JsonConsole()
    if fmt == "auto":
        fmt = "rich" if sys.stdout.isatty() else "plain"
    if fmt == "rich":
        try:
            return RichConsole(verbose=verbose, quiet=quiet)
        except Exception:
            return PlainConsole(verbose=verbose, quiet=quiet)   # fallback when rich is missing from the environment
    return PlainConsole(verbose=verbose, quiet=quiet)


class JsonConsole:
    """Dump events verbatim to stdout, one per line (machine-readable)."""

    def start(self, label: str) -> None:
        pass

    def handle(self, ev: Event) -> None:
        print(ev.to_json(), flush=True)

    def stop(self) -> None:
        pass


class _BaseTextConsole:
    """State tracking shared by plain / rich: stage, counts, confirmed-finding list."""

    def __init__(self, verbose: int = 0, quiet: bool = False):
        self.verbose = verbose
        self.quiet = quiet
        self._reset("")

    def _reset(self, label: str) -> None:
        """In batch scanning the console instance is reused across targets, so the previous target's state must be cleared before each one begins."""
        self.label = label
        self.stage = "connect"
        self.tool_index = 0
        self.tool_total = 0
        self.cur_tool = ""
        self.sink_done = 0
        self.sink_total = 0
        self.cur_activity = ""      # the detail currently being done (shown in the live UI, proving it is still running)
        self.counts = {"confirmed": 0, "suspected": 0, "clean": 0, "unreached": 0, "skipped": 0}
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
            self.cur_activity = "calling the LLM to identify sinks ..."
        elif ev.type == "sink.progress":
            self.sink_done = d.get("done", self.sink_done)
            self.sink_total = d.get("total", self.sink_total)
            self.cur_activity = f"classified tool {d.get('tool', '')}"
        elif ev.type == "sink.done":
            self.cur_activity = ""
        elif ev.type == "attack.plan":
            self.stage = "attack"
            self.cur_tool = d.get("tool", "")
            self.tool_index = d.get("index", self.tool_index)
            self.tool_total = d.get("total", self.tool_total)
            self.cur_activity = f"planning the call sequence for {d.get('tool', '')} ..."
        elif ev.type == "attack.param.start":
            self.cur_activity = f"firing payloads at {d.get('tool', '')}.{d.get('param', '')} ({d.get('payload_count', '?')} payloads, {d.get('sink', '')})"
        elif ev.type == "finding.confirmed":
            self.counts["confirmed"] += 1
            self.confirmed_findings.append(d)
        elif ev.type == "finding.suspected":
            self.counts["suspected"] += 1
        elif ev.type == "finding.clean":
            self.counts["clean"] += 1
        elif ev.type == "finding.unreached":
            self.counts["unreached"] += 1
        elif ev.type == "finding.skipped":
            self.counts["skipped"] += 1
        elif ev.type == "run.end":
            self.stage = "done"
            self.dry_run = bool(d.get("dry_run"))


STAGE_LABELS = {"connect": "connect", "sink": "sink inference", "attack": "attack", "done": "done"}


def _fmt_line(ev: Event) -> str | None:
    """Format one event into a line of human-readable text; return None if the event is not worth its own line (minor noise)."""
    d, t = ev.data, ev.type
    if t == "run.start":
        return f"start scan {d.get('url')} -> {d.get('run_dir')}"
    if t == "connect.ok":
        return (f"connected  {d.get('server_name') or '?'} {d.get('server_version') or ''}  "
                f"protocol {d.get('protocol_version')}  tools {d.get('tool_count')}")
    if t == "connect.fail":
        return f"connection failed  {d.get('error')}"
    if t == "gateway.reset":
        return f"[gateway] reset backend {d.get('server')} (reload, {d.get('when')}) -> clean state"
    if t == "gateway.wait":
        ok = "ready" if d.get("ready") else "not ready (timeout)"
        return f"[gateway] waited for backend {d.get('server')} {ok}, tools {d.get('tools')}"
    if t == "gateway.error":
        return f"[gateway] {d.get('error')}"
    if t == "sink.start":
        return f"inferring sinks ... ({d.get('tool_count')} tools)"
    if t == "sink.progress":
        return f"  sink progress {d.get('done')}/{d.get('total')}  ({d.get('tool')})"
    if t == "sink.labeled":
        # the event carries weights={class: weight} and provenance={class: [evidence]}; show the raised classes with their weight
        weights = d.get("weights", {})
        tags = ", ".join(f"{c}({weights.get(c)})" for c in d.get("provenance", {})) \
            or ", ".join(f"{c}({w})" for c, w in weights.items())
        return f"[sink] {d.get('tool')}.{d.get('param')} -> {tags}"
    if t == "sink.done":
        return f"sink inference done  {d.get('hot_count')}/{d.get('param_count')} parameters have candidates"
    if t == "attack.plan":
        note = f"  ({d.get('note')})" if d.get("note") else ""
        reach = "" if d.get("reachable", True) else "  [unreachable]"
        return (f"[plan] ({d.get('index')}/{d.get('total')}) {d.get('tool')}: "
                f"{d.get('steps')} steps, {d.get('param_count')} parameters to test{reach}{note}")
    if t == "server.crash":
        return f"⚠ server unresponsive (suspected DoS)  {d.get('tool')}: {d.get('note')}"
    if t == "attack.tool.error":
        return f"[error] {d.get('tool')} session error: {d.get('error')}"
    if t == "attack.tool.timeout":
        return (f"[timeout] ({d.get('index')}/{d.get('total')}) {d.get('tool')} "
                f"took {d.get('seconds')}s, exceeding the per-tool budget {int(d.get('budget', 0))}s -> abandoning this tool, moving to the next")
    if t == "launchpad.fail":
        return f"[not tested] {d.get('tool')}: {d.get('reason')}"
    if t == "launchpad.warn":
        return f"[incomplete prerequisites] {d.get('tool')}: {d.get('reason')} (still testing the target tool)"
    if t == "attack.param.start":
        return f"[attack] {d.get('tool')}.{d.get('param')} <- firing {d.get('payload_count')} payloads ({d.get('sink')})"
    if t == "payload.sent":
        flag = "✗" if d.get("is_error") else "✓"
        return f"  payload {flag} [{d.get('channel')}] {d.get('payload')!r}"
    if t == "finding.confirmed":
        return (f"● CONFIRMED  {d.get('tool')}.{d.get('param')}  ({d.get('sink')}, channel {d.get('channel')})\n"
                f"    payload: {d.get('payload')!r}\n"
                f"    evidence: {d.get('evidence')}")
    if t == "finding.suspected":
        note = f"  ({d.get('note')})" if d.get("note") else ""
        return (f"◐ SUSPECTED  {d.get('tool')}.{d.get('param')}  ({d.get('sink')}, channel {d.get('channel')})"
                f"{note}\n    evidence: {d.get('evidence')}")
    if t == "finding.clean":
        return f"○ likely clean  {d.get('tool')}.{d.get('param')}  ({d.get('sink')})"
    if t == "finding.unreached":
        note = f"  ({d.get('note')})" if d.get("note") else ""
        return f"○ unreached  {d.get('tool')}.{d.get('param')}  ({d.get('sink')}){note}"
    if t == "finding.skipped":
        note = f"  ({d.get('note')})" if d.get("note") else ""
        return f"⊘ not tested  {d.get('tool')}.{d.get('param')}  ({d.get('sink')}){note}"
    if t == "report.saved":
        return f"report saved: {d.get('path')}"
    if t == "run.end":
        if d.get("dry_run"):
            return "(dry-run, no payload was sent)"
        dos = d.get("dos", 0)
        dos_part = f" | suspected DoS {dos}" if dos else ""
        return (f"done  took {d.get('duration', 0):.1f}s  "
                f"confirmed {d.get('confirmed')} | suspected {d.get('suspected', 0)} | likely clean {d.get('clean')} | "
                f"unreached {d.get('unreached')} | not tested {d.get('skipped', 0)}{dos_part} | total {d.get('total')}")
    return None


class PlainConsole(_BaseTextConsole):
    """Non-TTY / --format plain: line-by-line timestamped output, no repaint, suited to pipes and CI."""

    def start(self, label: str) -> None:
        self._reset(label)
        print(f"=== {APP_NAME} ▸ {label} ===", flush=True)

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
    """TTY default: rich Live UI — status on top + scrolling log below; confirmed vulns in eye-catching red."""

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
        # Pass a dynamic render object + a higher frame rate: Live auto-refreshes per frame, so the timer/spinner move live.
        self._live = self._Live(_Dynamic(self._render), console=self.console,
                                refresh_per_second=12, transient=False)
        self._live.start()

    def handle(self, ev: Event) -> None:
        if ev.level == "debug" and self.verbose < 2:
            return
        self._update(ev)
        # sink.progress is only reflected in the top status bar, not flushed line-by-line into the scrolling log (otherwise a lot of noise lines)
        if ev.type != "sink.progress":
            line = _fmt_line(ev)
            if line is not None:
                self._append(ev, line)
        # Rendering is left to Live's auto-refresh (_Dynamic), no manual update needed here

    def stop(self) -> None:
        if self._live:
            self._live.stop()
        self._print_summary()

    # ---------- internal ----------

    def _append(self, ev: Event, line: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        style = None
        if ev.type == "finding.confirmed":
            style = "bold red"
        elif ev.type in ("connect.fail", "attack.tool.error", "server.crash"):
            style = "red"
        elif ev.type == "finding.suspected":
            style = "magenta"
        elif ev.type in ("launchpad.fail", "launchpad.warn", "finding.unreached", "finding.skipped",
                         "attack.tool.timeout"):
            style = "yellow"
        elif ev.type == "gateway.error":
            style = "yellow"
        elif ev.type in ("gateway.reset", "gateway.wait"):
            style = "cyan"
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
        header.add_row("target", self.label or "-")
        done = self.stage == "done"
        spin = "✓" if done else _SPINNER[int((time.time() - self._t0) * 12) % len(_SPINNER)]
        stage_line = f"{spin} {STAGE_LABELS.get(self.stage, self.stage)}"
        if self.stage == "sink" and self.sink_total:
            stage_line += f"  [{self.sink_done}/{self.sink_total} tools]"
        elif self.stage == "attack" and self.tool_total:
            stage_line += f"  [{self.tool_index}/{self.tool_total}]  current: {self.cur_tool}"
        header.add_row("stage", stage_line)
        if self.cur_activity and not done:
            header.add_row("doing", f"{self.cur_activity}")
        header.add_row("result", f"● confirmed {self.counts['confirmed']}   "
                               f"suspected {self.counts['suspected']}   likely clean {self.counts['clean']}   "
                               f"unreached {self.counts['unreached']}   not tested {self.counts['skipped']}")
        elapsed = int(time.time() - self._t0)
        header.add_row("elapsed", f"{elapsed // 60}:{elapsed % 60:02d}" if elapsed >= 60 else f"{elapsed}s")

        body = Text()
        for ts, line, style in list(self.log_lines):   # snapshot: Live renders on a background thread, avoid mutation during iteration
            body.append(f"{ts}  ", style="dim")
            body.append(line + "\n", style=style)

        return Group(
            Panel(header, title=APP_NAME, border_style="cyan"),
            Panel(body, title="live log", border_style="grey50", height=_LOG_HEIGHT + 2),
        )

    def _print_summary(self) -> None:
        from rich.table import Table
        if self.dry_run:
            self.console.print("[dim]dry-run: only previewed the attack surface, no payload was sent.[/dim]")
            return
        table = Table(title=f"detection summary — {self.label}")
        table.add_column("status")
        table.add_column("count", justify="right")
        table.add_row("[bold red]confirmed[/bold red]", str(self.counts["confirmed"]))
        table.add_row("[magenta]suspected[/magenta]", str(self.counts["suspected"]))
        table.add_row("likely clean", str(self.counts["clean"]))
        table.add_row("unreached", str(self.counts["unreached"]))
        table.add_row("not tested", str(self.counts["skipped"]))
        self.console.print(table)
        for f in self.confirmed_findings:
            self.console.print(f"  [bold red]●[/bold red] {f.get('tool')}.{f.get('param')}  "
                               f"({f.get('sink')}, channel {f.get('channel')})  payload: {f.get('payload')!r}")
