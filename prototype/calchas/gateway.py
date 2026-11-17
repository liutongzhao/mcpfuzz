"""mcphub 网关客户端：仅用于实验编排（重置/查询后端 MCP），不参与检测判定。

与检测核心解耦：检测器照常把 `/mcp/{server}` 当作一个普通 MCP URL 来扫描；本模块只
在扫描前后调用网关的管理 API 做"重置(reload)"和"确认状态"，以适配按需启动(on-demand)。
纯标准库；只认 mcphub 的通用管理 API，不含任何对被测服务的特判。

要点（2026-10-30 实测 v1.1.8）：
- 鉴权 header 是 `x-auth-token`（不是 Authorization: Bearer）。
- reload = `POST /api/servers/{name}/reload`，对 stdio 后端是杀进程重拉 = 状态归零。
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse


def server_name_from_url(url: str) -> str | None:
    """从 `/mcp/{server}` 直通端点 URL 解析后端服务器名；聚合口/智能路由/非该形式返回 None。"""
    parts = [p for p in urlparse(url).path.split("/") if p]
    if "mcp" in parts:
        rest = parts[parts.index("mcp") + 1:]
        if len(rest) == 1 and not rest[0].startswith("$"):
            return rest[0]
    return None


class GatewayClient:
    """mcphub 管理 API 的最小客户端。token 与 password 二选一（有 token 优先）。"""

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
            raise RuntimeError(f"网关 {method} {path} → HTTP {e.code}: {raw[:200]}") from None
        return json.loads(raw) if raw else {}

    def _login(self, user: str, password: str) -> str:
        d = self._req("POST", "/api/auth/login",
                      {"username": user, "password": password}, auth=False)
        tok = d.get("token")
        if not tok:
            raise RuntimeError(f"网关登录失败：{d.get('message')}")
        return tok

    def reload(self, server: str) -> dict:
        """强制重连上游：stdio 后端 = 杀进程重拉，回到干净状态（仅对已启用的后端有效）。"""
        return self._req("POST", f"/api/servers/{server}/reload")

    def enable(self, server: str) -> dict:
        """启用并连接后端：stdio 后端会被现场拉起进程，变 connected。用于"检测时才上线"。"""
        return self._req("POST", f"/api/servers/{server}/toggle", {"enabled": True})

    def disable(self, server: str) -> dict:
        """停用并断开后端：变 disconnected，并结束其 stdio 子进程（干净网关实测 add→disable 后子进程归 0）。
        数据集扫描的收尾用它（后端保留在网关里，下次再 enable）。
        注意：对「刚注册、仍在启动中」的后端立即 disable，可能触发 mcphub 内部 Connection closed 导致网关进程崩溃重启。"""
        return self._req("POST", f"/api/servers/{server}/toggle", {"enabled": False})

    def add(self, server: str, command: str, args: list[str], tries: int = 6, wait: float = 10.0) -> None:
        """注册一个 stdio 后端（仅大规模批量的「加→扫→删」模式使用；数据集扫描不调用）。
        mcphub 注册即自动启动该后端。网关暂时连不上（如正在重启）时等待后重试，不静默丢弃；
        已存在则视为成功。重试用尽仍失败则抛 RuntimeError，由调用方判「部署失败」。"""
        body = {"name": server, "config": {"type": "stdio", "command": command, "args": list(args), "env": {}}}
        last = ""
        for _ in range(max(1, tries)):
            try:
                self._req("POST", "/api/servers", body)
                return
            except RuntimeError as e:   # HTTP 错误：已存在算成功，其余直接上抛
                if "exist" in str(e).lower() or "已存在" in str(e):
                    return
                raise
            except (urllib.error.URLError, OSError) as e:   # 网关连不上：等它恢复
                last = str(e)
                time.sleep(wait)
        raise RuntimeError(f"注册后端 {server} 失败（网关持续不可用）：{last[:150]}")

    def delete(self, server: str) -> dict:
        """彻底移除后端（删除配置并结束其子进程）。仅大规模批量的「加→扫→删」模式在扫完后调用；
        数据集扫描绝不调用（数据集后端是预先注册好的，只能 enable/disable）。"""
        return self._req("DELETE", f"/api/servers/{server}")

    def server_record(self, server: str) -> dict | None:
        """查单个后端状态：用单后端端点 GET /api/servers/{name}，避开全量 /api/servers——
        后者会枚举所有后端并探测状态，在后端数量多时极慢甚至超时（批量部署后尤其明显）。"""
        try:
            d = self._req("GET", f"/api/servers/{server}")
        except RuntimeError:
            return None
        return d.get("data", d) or None

    def status(self, server: str) -> str | None:
        rec = self.server_record(server)
        return rec.get("status") if rec else None

    def wait_ready(self, server: str, timeout: float = 120.0, interval: float = 2.0) -> tuple[bool, int]:
        """轮询直到后端 status==connected **且已暴露工具(tools>0)**，返回 (ready, tool_count)。

        reload 刚发生时后端会被杀掉重拉（stdio 还要 npx 冷启动数秒），这期间网关会用自己的
        身份+空工具表应答 MCP 握手——必须等到真正就绪再开扫，否则会把"0 工具"当成功扫描。
        注意：按需启动(on-demand)的后端需先有一次 MCP 调用才会被拉起，对那类后端的预热应直接
        发 MCP 调用（fetch_catalog 即是），本方法用于 reload 后 / 常驻后端的就绪等待。"""
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
