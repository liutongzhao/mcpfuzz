"""判定器门面：串起探针登记、各通道观测与错误指纹，供判定引擎（executor）调用。

本层只做"低层观测物"：铸造带 token 的诱饵、匹配带内签名、查带外回连、识别错误指纹。
差分/时延比较、触达判定、证据聚合、五态裁决在判定引擎（orchestrator.executor）里完成。
"""
from __future__ import annotations

import os

from .fingerprint import error_fingerprint
from .oob import OOBChannel
from .probe import Hit, Probe, ProbeRegistry, mint_token
from .reflection import ReflectionChannel
from .verdict import Finding, decide

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
        """铸造探针。channel: oob（带外回连）| inband（带内回显/签名匹配）。"""
        token = mint_token()
        if channel == "oob":
            embed = self.oob.embed(token)
        elif channel in ("inband", "reflection"):
            embed = self.reflection.embed(token)
        else:
            raise ValueError(f"未知判定通道: {channel}")
        probe = Probe(token=token, channel=channel, embed=embed,
                      meta=meta or {}, expect=expect or [token])
        self.registry.add(probe)
        return probe

    def observe_inband(self, probe: Probe, response_text: str) -> Hit | None:
        """带内通道：在响应/报错文本里匹配 probe.expect（token 或特征签名）。"""
        return self.reflection.observe(probe, response_text)

    # 兼容旧名
    observe_response = observe_inband

    def poll(self, probes: list[Probe], rounds: int = 3, interval: float = 2.0) -> dict[str, Hit]:
        """带外通道：批量查命中。只对 channel=='oob' 的探针生效。"""
        return self.oob.poll(probes, rounds, interval)

    def fingerprint(self, text: str, vuln_class: str) -> str | None:
        """错误指纹（弱证据）。"""
        return error_fingerprint(text, vuln_class)

    def verdict(self, probe: Probe, hit: Hit | None) -> Finding:
        return decide(probe, hit)
