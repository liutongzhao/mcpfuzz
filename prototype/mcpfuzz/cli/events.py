"""事件模型：检测过程中的进展、发现与结论，用于驱动实时界面与日志落盘。

内核模块只管调 reporter.emit(...)；渲染成什么（终端 / run.log / events.jsonl）由
cli.console 和 cli.main 决定，内核不感知呈现方式——没挂任何 sink 时 emit 是静默的，
所以六个检测模块仍可被当作库直接调用，不强依赖 CLI。

事件词表（type）：
  run.start / run.end                    一次扫描的起止
  connect.ok / connect.fail              驱动层连接结果
  sink.start / sink.labeled / sink.done  sink 推断的进度与逐参数结果
  attack.plan                            编排器为某工具定的调用计划
  attack.tool.error                      该工具会话重试耗尽（标为未测成，不中断整体）
  launchpad.fail                         发射台没搭起来、目标实参取不到值（未测成）
  launchpad.warn                         前置步骤有失败但仍继续测试目标工具
  attack.param.start                     开始对某参数发载荷
  payload.sent                           每条载荷的发送结果（debug，仅 -vv）
  finding.confirmed / finding.clean / finding.unreached / finding.skipped   四态判定结论
  gateway.reset / gateway.error          经 mcphub 网关检测时：后端重置结果 / 网关异常
  report.saved                           报告落盘路径
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Event:
    type: str
    level: str = "info"        # info | debug（debug 默认不进终端，仅 -vv 或 events.jsonl）
    ts: float = field(default_factory=time.time)
    data: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps({"type": self.type, "level": self.level, "ts": self.ts, **self.data},
                           ensure_ascii=False, default=str)


class Reporter:
    """事件的扇出器：可挂多个 sink（可调用对象，接收一个 Event）。"""

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
                pass   # 呈现/落盘层的异常绝不能打断检测本身
        return ev


class JsonlSink:
    """落盘 events.jsonl：机读事件流，一次运行可完整回放，是复现实验的事实来源。"""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._fh = self.path.open("a", encoding="utf-8")

    def __call__(self, ev: Event) -> None:
        self._fh.write(ev.to_json() + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


class LogFileSink:
    """落盘 run.log：人读全量日志（不受 -q 影响，始终写全量）。"""

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


def _fmt_data(data: dict) -> str:
    parts = []
    for k, v in data.items():
        if k.lower() in _SECRET_KEYS:
            v = "***"
        s = str(v)
        if len(s) > 300:
            s = s[:300] + "…"
        parts.append(f"{k}={s}")
    return " ".join(parts)
