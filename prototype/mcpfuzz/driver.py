"""驱动层：连接 MCP 目标（Streamable HTTP），取回规范化工具清单。

基于官方 mcp SDK，不自行实现协议/传输。支持可选的 HTTP 头（如鉴权），
面向任意 MCP 服务通用，不针对具体靶机。
"""
from __future__ import annotations

import asyncio

from mcp import ClientSession
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

from .catalog import Target, normalize_tool


async def fetch_catalog(url: str, headers: dict | None = None, retries: int = 4) -> Target:
    """连接目标并返回规范化 Target。公网连接偶发抖动，做有限重试与退避。"""
    last = None
    for attempt in range(1, retries + 1):
        try:
            return await _fetch(url, headers)
        except Exception as e:
            last = e
            if attempt < retries:
                await asyncio.sleep(1.0 * attempt)
    raise RuntimeError(f"连接 {url} 失败（重试 {retries} 次）：{last}")


async def _fetch(url: str, headers: dict | None) -> Target:
    http_client = create_mcp_http_client(headers=headers) if headers else None
    captured: dict = {}
    try:
        async with streamable_http_client(url, http_client=http_client,
                                          terminate_on_close=False) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                result = await session.list_tools()
                captured["init"] = init
                captured["tools"] = result.tools
    except Exception:
        # 数据已取全时，吞掉会话拆解阶段的异常（SDK 关闭连接偶发报错）
        if "tools" not in captured:
            raise
    finally:
        if http_client is not None:
            await http_client.aclose()

    init = captured["init"]
    info = getattr(init, "server_info", None)
    proto = getattr(init, "protocol_version", None)
    tools = [normalize_tool(
                 t.name, t.description,
                 getattr(t, "input_schema", None) or getattr(t, "inputSchema", None) or {})
             for t in captured["tools"]]
    return Target(
        url=url,
        server_name=getattr(info, "name", None),
        server_version=getattr(info, "version", None),
        protocol_version=str(proto) if proto else None,
        tools=tools,
    )


def fetch_catalog_sync(url: str, headers: dict | None = None, retries: int = 4) -> Target:
    return asyncio.run(fetch_catalog(url, headers, retries))
