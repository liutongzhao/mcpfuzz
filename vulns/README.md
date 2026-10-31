# MCP 漏洞库

本目录收录 mcpfuzz 在各 MCP 服务上发现并核实的漏洞，供论文/复现/追踪使用。

## 约定
- 每个漏洞一份 `MCPVULN-NNN-<服务>-<slug>.md`，**顶部必须有 YAML 元数据头**（见 `TEMPLATE.md`）。
- 新增漏洞：复制 `TEMPLATE.md`，取下一个全局 ID（`MCPVULN-NNN`），填元数据与正文，并在下表登记一行。
- 关键元数据：**来自哪个 MCP 服务（mcp_service/version/package/source）**、工具.参数、类型(CWE)、严重度、
  状态（confirmed/suspected）、是否实测可利用、检测通道、发现日期、测试环境。
- `status=confirmed` 且 `confirmed_exploitable=true` 的才算"坐实可利用"。

## 索引

| ID | MCP 服务 | 工具.参数 | 类型 | 严重度 | 状态 | 可利用 | 发现日期 | 记录 |
|---|---|---|---|---|---|---|---|---|
| MCPVULN-001 | mcp-interactive-terminal@1.0.7 | send_command.input | 命令注入(CWE-78) | 严重 | confirmed | 是 | 2026-11-01 | [链接](MCPVULN-001-interactive-terminal-rce.md) |
