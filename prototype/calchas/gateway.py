"""mcphub gateway client: used only for experiment orchestration (reset/query of backend MCPs), not part of the detection verdict.

Decoupled from the detection core: the detector still scans `/mcp/{server}` as an ordinary MCP URL; this module
only calls the gateway's management API before/after a scan to "reset (reload)" and "confirm state", adapting to
on-demand startup. Pure standard library; only speaks mcphub's generic management API, with no special-casing of
any server under test.

Key points (verified on v1.1.8, 2026-10-30):
- The auth header is `x-auth-token` (not Authorization: Bearer).
- reload = `POST /api/servers/{name}/reload`; for a stdio backend this kills and respawns the process = state reset.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse


def server_name_from_url(url: str) -> str | None:
    """Parse the backend server name from a `/mcp/{server}` passthrough endpoint URL; returns None for an aggregate port / smart routing / a non-matching form."""
    parts = [p for p in urlparse(url).path.split("/") if p]
    if "mcp" in parts:
        rest = parts[parts.index("mcp") + 1:]
        if len(rest) == 1 and not rest[0].startswith("$"):
            return rest[0]
    return None


class GatewayClient:
    """Minimal client for the mcphub management API. token or password (token takes priority if both given)."""

    def __init__(self, base: str, token: str | None = None, user: str = "admin",
                 password: str | None = None, timeout: float = 10.0):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self._token = token
        if not self._token and password:
            self._token = self._login(user, password)

    def _req(self, method: str, path: str, body: dict | None = None, auth: bool = True) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{self.base}{path}", data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if auth and self._token:
            req.add_header("x-auth-token", self._token)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read().decode()
        except urllib.error.HTTPError as e:
            raw = e.read().decode(errors="replace")
            raise RuntimeError(f"gateway {method} {path} -> HTTP {e.code}: {raw[:200]}") from None
        return json.loads(raw) if raw else {}

    def _login(self, user: str, password: str) -> str:
        d = self._req("POST", "/api/auth/login",
                      {"username": user, "password": password}, auth=False)
        tok = d.get("token")
        if not tok:
            raise RuntimeError(f"gateway login failed: {d.get('message')}")
        return tok

    def reload(self, server: str) -> dict:
        """Force a reconnect to the upstream: for a stdio backend = kill and respawn the process, back to a clean state (only effective on an already-enabled backend)."""
        return self._req("POST", f"/api/servers/{server}/reload")

    def enable(self, server: str) -> dict:
        """Enable and connect the backend: a stdio backend has its process spawned on the spot, becoming connected. Used for "enable only during detection"."""
        return self._req("POST", f"/api/servers/{server}/toggle", {"enabled": True})

    def disable(self, server: str) -> dict:
        """Disable and disconnect the backend: becomes disconnected, and its stdio child process ends (on a clean gateway, add->disable brings child processes to 0).
        Used at the finish of dataset scanning (the backend stays registered in the gateway, re-enabled next time).
        Note: disabling a "just-registered, still-starting" backend immediately may trigger an mcphub-internal Connection closed and crash/restart the gateway process."""
        return self._req("POST", f"/api/servers/{server}/toggle", {"enabled": False})

    def add(self, server: str, command: str, args: list[str], tries: int = 6, wait: float = 10.0) -> None:
        """Register a stdio backend (only used by the "add -> scan -> delete" mode of large-scale batches; dataset scanning does not call it).
        mcphub auto-starts the backend on registration. When the gateway is temporarily unreachable (e.g. restarting), wait and retry instead of silently dropping;
        an already-existing one counts as success. If retries are exhausted it raises RuntimeError, for the caller to judge "deploy failure"."""
        body = {"name": server, "config": {"type": "stdio", "command": command, "args": list(args), "env": {}}}
        last = ""
        for _ in range(max(1, tries)):
            try:
                self._req("POST", "/api/servers", body)
                return
            except RuntimeError as e:   # HTTP error: "already exists" counts as success, otherwise re-raise
                # match both the English and the Chinese-locale mcphub "already exists" wording, so a duplicate registration is treated as success
                if "exist" in str(e).lower() or "已存在" in str(e):
                    return
                raise
            except (urllib.error.URLError, OSError) as e:   # gateway unreachable: wait for it to recover
                last = str(e)
                time.sleep(wait)
        raise RuntimeError(f"failed to register backend {server} (gateway persistently unavailable): {last[:150]}")

    def delete(self, server: str) -> dict:
        """Completely remove the backend (delete the config and end its child process). Only called by the "add -> scan -> delete" mode of large-scale batches after the scan;
        dataset scanning never calls it (dataset backends are pre-registered, only enable/disable)."""
        return self._req("DELETE", f"/api/servers/{server}")

    def server_record(self, server: str) -> dict | None:
        """Query a single backend's state: use the single-backend endpoint GET /api/servers/{name}, avoiding the full /api/servers —
        the latter enumerates all backends and probes their state, which is extremely slow or even times out when there are many backends (especially noticeable after a batch deploy)."""
        try:
            d = self._req("GET", f"/api/servers/{server}")
        except RuntimeError:
            return None
        return d.get("data", d) or None

    def status(self, server: str) -> str | None:
        rec = self.server_record(server)
        return rec.get("status") if rec else None

    def wait_ready(self, server: str, timeout: float = 120.0, interval: float = 2.0) -> tuple[bool, int]:
        """Poll until the backend status==connected **and it has exposed tools (tools>0)**, returning (ready, tool_count).

        Just after a reload, the backend is killed and respawned (stdio still needs a few seconds of npx cold start),
        during which the gateway answers the MCP handshake with its own identity + an empty tool list — one must wait
        for true readiness before scanning, otherwise "0 tools" is taken as a successful scan.
        Note: an on-demand backend is only spawned after a first MCP call, so warming such a backend should directly
        send an MCP call (fetch_catalog does this); this method is for readiness-waiting after a reload / for persistent backends."""
        deadline = time.time() + timeout
        n = 0
        while time.time() < deadline:
            rec = self.server_record(server)
            if rec and rec.get("status") == "connected":
                n = len(rec.get("tools") or [])
                if n > 0:
                    return True, n
            time.sleep(interval)
        return False, n
