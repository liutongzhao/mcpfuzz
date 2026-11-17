"""Event model: progress, findings and conclusions during detection, used to drive the live UI and log persistence.

Core modules only call reporter.emit(...); what it renders into (terminal / run.log / events.jsonl) is decided
by cli.console and cli.main, and the core is unaware of the presentation — with no sink attached, emit is
silent, so the six detection modules can still be called directly as a library, with no hard dependency on the CLI.

Event vocabulary (type):
  run.start / run.end                    start/end of one scan
  connect.ok / connect.fail              driver-layer connection result
  sink.start / sink.labeled / sink.done  sink inference progress and per-parameter result
  attack.plan                            the call plan the orchestrator / sequence construction set for a tool
  agent.round / agent.done / agent.cache_hit / agent.error   sequence-construction agent loop progress (debug)
  attack.tool.error                      the tool's session retries were exhausted (marked not-tested, does not interrupt the whole run)
  launchpad.fail                         the launch pad could not be built, the target's arguments could not be resolved (not tested)
  launchpad.warn                         a prerequisite step failed but testing of the target tool continues
  launchpad.step                         send detail of each prerequisite step (debug: args/response/error body)
  launchpad.ready                        the target tool's launch-pad baseline is ready, incl. baseline response/latency (debug)
  attack.param.start                     begin sending payloads for a parameter
  payload.sent                           send result of each probe (debug, only -vv; the file includes args/response/error/latency)
  finding.confirmed / finding.suspected / finding.clean / finding.unreached / finding.skipped   five-state verdicts
  gateway.reset / gateway.error          when detecting via the mcphub gateway: backend reset result / gateway error
  report.saved                           report persistence path
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Event:
    type: str
    level: str = "info"        # info | debug (debug does not reach the terminal by default, only -vv or events.jsonl)
    ts: float = field(default_factory=time.time)
    data: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps({"type": self.type, "level": self.level, "ts": self.ts, **self.data},
                           ensure_ascii=False, default=str)


class Reporter:
    """Event fan-out: can attach several sinks (callables that receive one Event)."""

    def __init__(self):
        self._sinks: list = []

    def add_sink(self, fn) -> None:
        self._sinks.append(fn)

    def emit(self, type: str, level: str = "info", **data) -> Event:
        ev = Event(type=type, level=level, data=data)
        for fn in self._sinks:
            try:
                fn(ev)
            except Exception:
                pass   # an exception in the presentation/persistence layer must never interrupt detection itself
        return ev


class JsonlSink:
    """Persist events.jsonl: a machine-readable event stream, fully replayable for one run, the source of truth for reproducing experiments."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._fh = self.path.open("a", encoding="utf-8")

    def __call__(self, ev: Event) -> None:
        self._fh.write(ev.to_json() + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


class LogFileSink:
    """Persist run.log: a human-readable full log (unaffected by -q, always writes everything)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._fh = self.path.open("a", encoding="utf-8")

    def __call__(self, ev: Event) -> None:
        t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ev.ts))
        line = f"[{t}] [{ev.level:5s}] {ev.type}  {_fmt_data(ev.data)}"
        self._fh.write(line + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


_SECRET_KEYS = {"authorization", "api_key", "apikey", "token", "headers"}


# run.log is for human debugging, so keep it long: response/error bodies and nested arguments must be fully
# visible, to diagnose the real cause of "unreached/errored". The true machine-readable, fully-replayable source
# of truth is events.jsonl (not truncated).
_LOGFILE_CAP = 4000


def _fmt_data(data: dict) -> str:
    parts = []
    for k, v in data.items():
        if k.lower() in _SECRET_KEYS:
            v = "***"
        s = str(v)
        if len(s) > _LOGFILE_CAP:
            s = s[:_LOGFILE_CAP] + f"...(truncated, {len(s)} chars total, see events.jsonl for the full content)"
        parts.append(f"{k}={s}")
    return " ".join(parts)
