"""载荷合成：给一个带 sink 标注的参数 + 判定器，产出一批有序、自带探针的载荷。

- 只对第一期的 sink 出载荷：命令注入 / SSRF / 路径穿越（读）。
- 每条载荷绑定一个判定器探针（唯一 token），并按"最可能命中"排序以支持早停。
- 载荷层只管 sink 语法，诱饵（回连URL/标记）来自判定器——保持解耦。
"""
from __future__ import annotations

from pathlib import Path

from mcpfuzz.sink.types import CI, PT, SSRF

from .types import Payload

DICT_DIR = Path(__file__).resolve().parent / "dicts"
PHASE1_SINKS = {CI, SSRF, PT}
# 路径穿越读 /etc/passwd 的稳定特征串（回显通道据此匹配）
PATH_SIGNATURES = ["root:x:0:0:", "root:x:0:0", "daemon:x:"]


def _load_dict(sink: str) -> list[str]:
    path = DICT_DIR / f"{sink}.txt"
    if not path.exists():
        return []
    lines = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if s and not s.startswith("#"):
            lines.append(raw.rstrip("\n"))
    return lines


class PayloadSynthesizer:
    def __init__(self, oracle):
        self.oracle = oracle
        self.dicts = {s: _load_dict(s) for s in PHASE1_SINKS}

    def synthesize(self, param_sink) -> list[Payload]:
        """param_sink: sink.types.ParamSink。返回按 rank 排好序的载荷列表。"""
        labels = [l for l in param_sink.sinks if l.type in PHASE1_SINKS]
        labels.sort(key=lambda l: 0 if l.confidence == "high" else 1)  # 高置信 sink 先打
        out: list[Payload] = []
        for lab in labels:
            out += self._for_sink(param_sink.tool, param_sink.param_path, lab.type)
        for i, p in enumerate(out):
            p.rank = i
        return out

    def _for_sink(self, tool: str, param_path: str, sink: str) -> list[Payload]:
        out: list[Payload] = []
        for line in self.dicts.get(sink, []):
            if sink == PT:
                probe = self.oracle.new_probe("reflection",
                                              meta={"tool": tool, "param": param_path, "sink": sink,
                                                    "payload": line},
                                              expect=PATH_SIGNATURES)
                out.append(Payload(tool, param_path, line, sink, "reflection", probe,
                                   technique=f"pt:{line[:20]}"))
            elif "{{TOKEN}}" in line:
                probe = self.oracle.new_probe("reflection",
                                              meta={"tool": tool, "param": param_path, "sink": sink})
                value = line.replace("{{TOKEN}}", probe.embed).replace("\\n", "\n")
                probe.meta["payload"] = value
                out.append(Payload(tool, param_path, value, sink, "reflection", probe,
                                   technique=f"{sink[:2]}:echo-token"))
            else:  # 含 {{CALLBACK}} 或 SSRF 的纯回连 URL → OOB
                probe = self.oracle.new_probe("oob",
                                              meta={"tool": tool, "param": param_path, "sink": sink})
                value = line.replace("{{CALLBACK}}", probe.embed).replace("\\n", "\n")
                probe.meta["payload"] = value
                out.append(Payload(tool, param_path, value, sink, "oob", probe,
                                   technique=f"{sink[:3]}:{line[:14]}"))
        return out
