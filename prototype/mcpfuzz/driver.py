"""驱动层：连接 MCP 目标（Streamable HTTP），取回规范化工具清单。

基于官方 mcp SDK 的高层 Client，不自行实现协议/传输。
"""
from __future__ import annotations

import asyncio

from mcp import Client

from .catalog import Target, normalize_tool


async def fetch_catalog(url: str, retries: int = 3) -> Target:
    """连接目标并返回规范化的 Target。连接建立偶发抖动，做有限重试。"""
    last = None
    for attempt in range(1, retries + 1):
        try:
            return await _fetch(url)
        except Exception as e:  # 连接/协议异常都重试
            last = e
            if attempt < retries:
                await asyncio.sleep(1.5 * attempt)
    raise RuntimeError(f"连接 {url} 失败（重试 {retries} 次）：{last}")


async def _fetch(url: str) -> Target:
    async with Client(url) as client:
        info = client.server_info
        proto = client.protocol_version
        result = await client.list_tools()
        raw_tools = result.tools if hasattr(result, "tools") else result
        tools = [normalize_tool(
                     t.name, t.description,
                     getattr(t, "input_schema", None) or getattr(t, "inputSchema", None) or {})
                 for t in raw_tools]
    return Target(
        url=url,
        server_name=getattr(info, "name", None),
        server_version=getattr(info, "version", None),
        protocol_version=str(proto) if proto else None,
        tools=tools,
    )


def fetch_catalog_sync(url: str, retries: int = 3) -> Target:
    return asyncio.run(fetch_catalog(url, retries))
