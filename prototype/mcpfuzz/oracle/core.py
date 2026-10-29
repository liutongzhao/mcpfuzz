"""判定器门面：串起探针登记、各通道与裁决，对外提供四个动作。

new_probe   —— 铸造探针（唯一 token + 可嵌入物），登记溯源。
observe_response —— 同步通道（回显）：扫返回文本。
poll        —— 异步通道（OOB）：查采集服务。
verdict     —— 给出判定结论。
"""
from __future__ import annotations

import os

from .oob import OOBChannel
from .probe import Hit, Probe, ProbeRegistry, mint_token
from .reflection import ReflectionChannel
from .verdict import Finding, decide

# 配置（可被构造参数或环境变量覆盖；不进入检测逻辑）
DEFAULT_OOB_CALLBACK = os.environ.get("MCP_OOB_CALLBACK", "http://43.133.80.249:9100")
DEFAULT_OOB_QUERY = os.environ.get("MCP_OOB_QUERY", "http://43.133.80.249:9100/__hits")


class Oracle:
    def __init__(self, oob_callback_base: str = DEFAULT_OOB_CALLBACK,
                 oob_query_url: str = DEFAULT_OOB_QUERY):
        self.registry = ProbeRegistry()
        self.oob = OOBChannel(oob_callback_base, oob_query_url)
        self.reflection = ReflectionChannel()

    def new_probe(self, channel: str, meta: dict | None = None,
                  expect: list | None = None) -> Probe:
        token = mint_token()
        if channel == "oob":
            embed = self.oob.embed(token)
        elif channel == "reflection":
            embed = self.reflection.embed(token)
        else:
            raise ValueError(f"未知判定通道: {channel}")
        probe = Probe(token=token, channel=channel, embed=embed,
                      meta=meta or {}, expect=expect or [token])
        self.registry.add(probe)
        return probe

    def observe_response(self, probe: Probe, response_text: str) -> Hit | None:
        if probe.channel != "reflection":
            return None
        return self.reflection.observe(probe, response_text)

    def poll(self, probes: list[Probe], rounds: int = 3, interval: float = 2.0) -> dict[str, Hit]:
        return self.oob.poll(probes, rounds, interval)

    def verdict(self, probe: Probe, hit: Hit | None) -> Finding:
        return decide(probe, hit)
