"""带外回连(OOB)通道：采集服务的客户端。

- embed(token)：给出载荷里要回连的 URL。
- poll(probes)：查采集服务，哪些 token 回连了，返回命中证据。
采集服务见 deploy/infra/oob（任意请求 /<token> 记为命中，GET /__hits 查询）。
"""
from __future__ import annotations

import json
import time
import urllib.request

from .probe import Hit, Probe


class OOBChannel:
    def __init__(self, callback_base: str, query_url: str, timeout: float = 10):
        self.callback_base = callback_base.rstrip("/")
        self.query_url = query_url
        self.timeout = timeout

    def embed(self, token: str) -> str:
        return f"{self.callback_base}/{token}"

    def _get(self, url: str) -> dict:
        with urllib.request.urlopen(url, timeout=self.timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))

    def poll(self, probes: list[Probe], rounds: int = 3, interval: float = 2.0) -> dict[str, Hit]:
        """批量查命中，带观测窗口以捕获晚到的回连。返回 {token: Hit}。"""
        targets = [p for p in probes if p.channel == "oob"]
        if not targets:
            return {}
        hits: dict[str, Hit] = {}
        for rnd in range(rounds):
            try:
                counts = self._get(self.query_url).get("tokens", {})
            except Exception:
                counts = {}
            for p in targets:
                if p.token in counts and p.token not in hits:
                    try:
                        detail = self._get(f"{self.query_url}?token={p.token}")
                        rec = (detail.get("records") or [{}])[0]
                    except Exception:
                        rec = {}
                    hits[p.token] = Hit(p.token, "oob", rec.get("time"), rec)
            if len(hits) == len(targets):
                break
            if rnd < rounds - 1:
                time.sleep(interval)
        return hits
