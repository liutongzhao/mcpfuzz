"""Response-reflection channel: match an agreed marker in the tool's returned text.

- embed(token): produce the marker the payload should reflect back (defaults to the token itself).
- observe(probe, response_text): return a Hit (with the matched snippet) on a hit.
Also used for path-traversal reads — there probe.expect holds the signature string of the out-of-bounds file.
"""
from __future__ import annotations

import time

from .probe import Hit, Probe


class ReflectionChannel:
    def embed(self, token: str) -> str:
        return token

    def observe(self, probe: Probe, response_text: str) -> Hit | None:
        if not response_text:
            return None
        for marker in (probe.expect or [probe.token]):
            if marker and marker in response_text:
                i = response_text.find(marker)
                snippet = response_text[max(0, i - 40): i + len(marker) + 40]
                return Hit(probe.token, "reflection", time.strftime("%Y-%m-%dT%H:%M:%S"),
                           {"marker": marker, "snippet": snippet})
        return None
