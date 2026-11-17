"""Driver layer: connect to an MCP target (Streamable HTTP), list tools / call tools.

Built on the official mcp SDK, without implementing the protocol/transport ourselves. Supports optional HTTP
headers (e.g. for auth), generic across any MCP service.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from mcp import ClientSession
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

from .catalog import Target, nest_arguments, normalize_tool


def _make_http_client(headers: dict | None, timeout: float | None):
    if not headers and not timeout:
        return None
    # Build the Timeout using the same httpx module the mcp SDK itself uses: different mcp versions may use
    # httpx or httpx2 underneath, and the type must match the SDK's, otherwise the SDK's internal timeout
    # arithmetic raises a type error like "float + Timeout" (connecting via the gateway failed exactly this way
    # after upgrading to mcp 1.30). Prefer the httpx inside the SDK module, falling back to importing it ourselves.
    from mcp.client import streamable_http as _sh
    _httpx = getattr(_sh, "httpx", None)
    if _httpx is None:
        try:
            import httpx as _httpx
        except ImportError:  # older environments use the httpx2 replacement package
            import httpx2 as _httpx
    t = None
    if timeout:
        # read must be generous: a streamable-HTTP response goes over SSE, and the server keeps the stream open
        # for a long time waiting for the result; squeezing read down to the same short value as connect/write/pool
        # would cut it off before the stream has emitted any data.
        t = _httpx.Timeout(timeout, read=max(timeout, 300.0))
    return create_mcp_http_client(headers=headers or None, timeout=t)


async def _with_session(url: str, headers: dict | None, fn, timeout: float | None = None):
    """Establish a session, execute fn(session, init) and return its result.

    terminate_on_close=False and, after obtaining the result, swallow teardown-phase exceptions (the SDK occasionally errors while closing the connection).
    """
    http_client = _make_http_client(headers, timeout)
    captured: dict = {}
    try:
        async with streamable_http_client(url, http_client=http_client,
                                          terminate_on_close=False) as (read, write, *_):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                captured["result"] = await fn(session, init)
    except Exception:
        if "result" not in captured:
            raise
    finally:
        if http_client is not None:
            await http_client.aclose()
    return captured["result"]


async def _retry(coro_factory, what: str, url: str, retries: int):
    last = None
    for attempt in range(1, retries + 1):
        try:
            return await coro_factory()
        except Exception as e:
            last = e
            if attempt < retries:
                await asyncio.sleep(1.0 * attempt)
    raise RuntimeError(f"{what} {url} failed (after {retries} retries): {last}")


# ---------- list tools ----------

async def fetch_catalog(url: str, headers: dict | None = None, retries: int = 4,
                        timeout: float | None = None) -> Target:
    async def once():
        info, proto, tools = await _with_session(url, headers, _collect_tools, timeout)
        return Target(url=url,
                      server_name=getattr(info, "name", None),
                      server_version=getattr(info, "version", None),
                      protocol_version=str(proto) if proto else None,
                      tools=tools)
    return await _retry(once, "connect", url, retries)


async def _collect_tools(session, init):
    result = await session.list_tools()
    tools = [normalize_tool(
                 t.name, t.description,
                 getattr(t, "input_schema", None) or getattr(t, "inputSchema", None) or {})
             for t in result.tools]
    return getattr(init, "server_info", None), getattr(init, "protocol_version", None), tools


# ---------- call tool ----------

async def call_tool(url: str, tool: str, arguments: dict,
                    headers: dict | None = None, retries: int = 3,
                    timeout: float | None = None) -> dict:
    """Call one tool, returning {text, is_error, raw}. text is the plain text of the returned content concatenated."""
    async def once():
        return await _with_session(url, headers, lambda s, i: _do_call(s, tool, arguments), timeout)
    return await _retry(once, f"call {tool}", url, retries)


async def _do_call(session, tool, arguments):
    # Before sending, rebuild the flat dotted/bracketed-key arguments into the nested structure the tool expects
    # (symmetric with flatten_schema). This is the single global tools/call exit, so placing it here lets payload
    # calls, prerequisite steps and the fallback plan all benefit uniformly.
    sent = nest_arguments(arguments)
    res = await session.call_tool(tool, sent)
    content = getattr(res, "content", None) or []
    text = "\n".join((getattr(b, "text", "") or "") for b in content)
    is_error = getattr(res, "is_error", getattr(res, "isError", False))
    # args_sent returns the actual nested arguments sent on the wire, so the log records them faithfully (for debug reproduction).
    return {"text": text, "is_error": bool(is_error), "raw": res, "args_sent": sent}


# ---------- synchronous wrappers ----------

def fetch_catalog_sync(url: str, headers: dict | None = None, retries: int = 4,
                       timeout: float | None = None) -> Target:
    return asyncio.run(fetch_catalog(url, headers, retries, timeout))


def call_tool_sync(url: str, tool: str, arguments: dict,
                   headers: dict | None = None, retries: int = 3,
                   timeout: float | None = None) -> dict:
    return asyncio.run(call_tool(url, tool, arguments, headers, retries, timeout))


# ---------- persistent session (one connection shared by a call sequence) ----------

@asynccontextmanager
async def open_session(url: str, headers: dict | None = None, timeout: float | None = None):
    """Open and initialize a session for reuse by multiple call_on; closed on exit.

    Key: only swallow exceptions from "after a successful yield" (the session-teardown phase, where the SDK
    occasionally errors); a failure before yield (connection/initialization) must be raised. Otherwise the
    generator "ends without yielding", and the caller's `async with` raises a meaningless
    `RuntimeError: generator didn't yield`, completely masking the real error (connection refused /
    initialization failure / server unresponsive) — which was exactly the root cause of a whole scan round
    cascading into failure from midway, while the log left only a single `generator didn't yield`.
    """
    http_client = _make_http_client(headers, timeout)
    yielded = False
    body_failed = False
    try:
        async with streamable_http_client(url, http_client=http_client,
                                          terminate_on_close=False) as (read, write, *_):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yielded = True
                try:
                    yield session
                except BaseException:
                    # The exception comes from the with body (the caller), injected into this yield point via athrow.
                    # It must be raised, never swallowed like a "teardown-phase occasional error": otherwise the body's
                    # return is lost, async with swallows the exception and exits successfully, the caller gets None
                    # (neither a result nor an exception), and then blows up at an upper layer at `findings += None` /
                    # `res.get(...)` (intermittently, extremely hard to locate).
                    body_failed = True
                    raise
    except Exception:
        if not yielded or body_failed:
            raise  # failure before yield (connection/initialization) or body failure -> raise, for the upper layer to retry / record the real reason
        # only an "SDK occasional error in the pure teardown phase after a successful yield": the result was already collected in the body, so swallow it
    finally:
        if http_client is not None:
            await http_client.aclose()


async def ping(url: str, headers: dict | None = None, timeout: float | None = None,
               raise_on_fail: bool = False) -> bool:
    """Lightweight liveness probe: only establish a session and initialize; return True on success.

    Used to distinguish "the server was beaten down / unresponsive" (a result, even a DoS signal) from "a
    client-side session anomaly" (a bug). When raise_on_fail=True, a failure does not return False but raises the
    real exception, for the upper layer to record the crash reason — avoiding silently swallowing "why the probe
    failed", which would make a real DoS indistinguishable from a false positive in the log.
    """
    try:
        await _with_session(url, headers, lambda s, i: True, timeout)
        return True
    except Exception:
        if raise_on_fail:
            raise
        return False


async def call_on(session, tool: str, arguments: dict) -> dict:
    """Call one tool on an existing session, returning {text, is_error, raw}."""
    return await _do_call(session, tool, arguments)
