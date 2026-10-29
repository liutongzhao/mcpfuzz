"""驱动层：连接 MCP 目标（Streamable HTTP），列工具 / 调用工具。

基于官方 mcp SDK，不自行实现协议/传输。支持可选 HTTP 头（如鉴权），面向任意 MCP 服务通用。
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from mcp import ClientSession
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

from .catalog import Target, normalize_tool


def _make_http_client(headers: dict | None, timeout: float | None):
    if not headers and not timeout:
        return None
    import httpx2   # mcp SDK 底层用的 httpx 替代包（这个环境里的网络层），不是标准 httpx
    t = None
    if timeout:
        # read 必须留足：streamable HTTP 的响应走 SSE，服务器会把流长时间开着等结果；
        # 把 read 也压到跟 connect/write/pool 一样短，会在流还没吐数据时就被掐断
        # （表现为 "Server disconnected without sending a response"）。connect/write/pool
        # 仍用用户给的 timeout 快速失败，read 给个不低于 SDK 默认(300s)的下限。
        t = httpx2.Timeout(timeout, read=max(timeout, 300.0))
    return create_mcp_http_client(headers=headers, timeout=t)


async def _with_session(url: str, headers: dict | None, fn, timeout: float | None = None):
    """建立会话，执行 fn(session, init) 并返回其结果。

    terminate_on_close=False 并在取到结果后吞掉拆解阶段异常（SDK 关闭连接偶发报错）。
    """
    http_client = _make_http_client(headers, timeout)
    captured: dict = {}
    try:
        async with streamable_http_client(url, http_client=http_client,
                                          terminate_on_close=False) as (read, write):
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
    raise RuntimeError(f"{what} {url} 失败（重试 {retries} 次）：{last}")


# ---------- 列工具 ----------

async def fetch_catalog(url: str, headers: dict | None = None, retries: int = 4,
                        timeout: float | None = None) -> Target:
    async def once():
        info, proto, tools = await _with_session(url, headers, _collect_tools, timeout)
        return Target(url=url,
                      server_name=getattr(info, "name", None),
                      server_version=getattr(info, "version", None),
                      protocol_version=str(proto) if proto else None,
                      tools=tools)
    return await _retry(once, "连接", url, retries)


async def _collect_tools(session, init):
    result = await session.list_tools()
    tools = [normalize_tool(
                 t.name, t.description,
                 getattr(t, "input_schema", None) or getattr(t, "inputSchema", None) or {})
             for t in result.tools]
    return getattr(init, "server_info", None), getattr(init, "protocol_version", None), tools


# ---------- 调用工具 ----------

async def call_tool(url: str, tool: str, arguments: dict,
                    headers: dict | None = None, retries: int = 3,
                    timeout: float | None = None) -> dict:
    """调用一个工具，返回 {text, is_error, raw}。text 为返回内容拼接的纯文本。"""
    async def once():
        return await _with_session(url, headers, lambda s, i: _do_call(s, tool, arguments), timeout)
    return await _retry(once, f"调用 {tool}", url, retries)


async def _do_call(session, tool, arguments):
    res = await session.call_tool(tool, arguments)
    content = getattr(res, "content", None) or []
    text = "\n".join((getattr(b, "text", "") or "") for b in content)
    is_error = getattr(res, "is_error", getattr(res, "isError", False))
    return {"text": text, "is_error": bool(is_error), "raw": res}


# ---------- 同步封装 ----------

def fetch_catalog_sync(url: str, headers: dict | None = None, retries: int = 4,
                       timeout: float | None = None) -> Target:
    return asyncio.run(fetch_catalog(url, headers, retries, timeout))


def call_tool_sync(url: str, tool: str, arguments: dict,
                   headers: dict | None = None, retries: int = 3,
                   timeout: float | None = None) -> dict:
    return asyncio.run(call_tool(url, tool, arguments, headers, retries, timeout))


# ---------- 持久会话（一条调用序列共用一个连接） ----------

@asynccontextmanager
async def open_session(url: str, headers: dict | None = None, timeout: float | None = None):
    """打开并初始化一个会话，供多次 call_on 复用；退出时关闭（吞掉拆解异常）。"""
    http_client = _make_http_client(headers, timeout)
    try:
        async with streamable_http_client(url, http_client=http_client,
                                          terminate_on_close=False) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session
    except Exception:
        pass  # 会话拆解阶段 SDK 偶发报错，调用结果已在外层收集
    finally:
        if http_client is not None:
            await http_client.aclose()


async def call_on(session, tool: str, arguments: dict) -> dict:
    """在已有会话上调用一个工具，返回 {text, is_error, raw}。"""
    return await _do_call(session, tool, arguments)
