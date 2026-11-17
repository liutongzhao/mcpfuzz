"""Oracle facade: wires together probe registration, per-channel observation and error fingerprints, for
the verdict engine (executor) to call.

This layer only produces "low-level observables": minting token-bearing decoys, matching in-band signatures,
querying OOB callbacks, recognizing error fingerprints. Differential/timing comparison, reachability
judgement, evidence aggregation and the five-state verdict are done in the verdict engine (orchestrator.executor).
"""
from __future__ import annotations

import os

from .fingerprint import error_fingerprint
from .oob import OOBChannel
from .probe import Hit, Probe, ProbeRegistry, mint_token
from .reflection import ReflectionChannel
from .verdict import Finding, decide

# OOB callback is off unless configured; no server is baked into the package.
DEFAULT_OOB_CALLBACK = os.environ.get("MCP_OOB_CALLBACK", "")
DEFAULT_OOB_QUERY = os.environ.get("MCP_OOB_QUERY", "")


class Oracle:
    def __init__(self, oob_callback_base: str = DEFAULT_OOB_CALLBACK,
                 oob_query_url: str = DEFAULT_OOB_QUERY):
        self.registry = ProbeRegistry()
        # The bundled collector serves hits at <callback>/__hits, so the query URL defaults to that.
        if oob_callback_base and not oob_query_url:
            oob_query_url = oob_callback_base.rstrip("/") + "/__hits"
        self.oob = OOBChannel(oob_callback_base, oob_query_url)
        self.reflection = ReflectionChannel()
        # the out-of-band channel is only usable when a callback base is given
        self.oob_enabled = bool(oob_callback_base and oob_query_url)

    def new_probe(self, channel: str, meta: dict | None = None,
                  expect: list | None = None) -> Probe:
        """Mint a probe. channel: oob (out-of-band callback) | inband (in-band reflection / signature match)."""
        token = mint_token()
        if channel == "oob":
            embed = self.oob.embed(token)
        elif channel in ("inband", "reflection"):
            embed = self.reflection.embed(token)
        else:
            raise ValueError(f"unknown verdict channel: {channel}")
        probe = Probe(token=token, channel=channel, embed=embed,
                      meta=meta or {}, expect=expect or [token])
        self.registry.add(probe)
        return probe

    def observe_inband(self, probe: Probe, response_text: str) -> Hit | None:
        """In-band channel: match probe.expect (token or signature) in the response/error text."""
        return self.reflection.observe(probe, response_text)

    # legacy alias
    observe_response = observe_inband

    def poll(self, probes: list[Probe], rounds: int = 3, interval: float = 2.0) -> dict[str, Hit]:
        """Out-of-band channel: query hits in batch. Applies only to probes with channel=='oob'."""
        return self.oob.poll(probes, rounds, interval)

    def fingerprint(self, text: str, vuln_class: str) -> str | None:
        """Error fingerprint (weak evidence)."""
        return error_fingerprint(text, vuln_class)

    def verdict(self, probe: Probe, hit: Hit | None) -> Finding:
        return decide(probe, hit)
