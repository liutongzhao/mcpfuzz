---
id: MCPVULN-XXX
mcp_service: <服务名，如 mcp-interactive-terminal>
mcp_version: <版本>
mcp_package: "<包标识，如 mcp-interactive-terminal@1.0.7>"
source: <来源，如 npm / pypi / github / docker>
tool: <工具名>
param: <注入点参数>
vuln_type: <command_injection|argument_injection|path_traversal|ssrf|query_injection|code_injection|other>
cwe: <CWE-XX>
severity: <critical|high|medium|low>
status: <confirmed|suspected|fixed|reported>          # confirmed=有铁证；suspected=仅弱证据
confirmed_exploitable: <true|false>                   # 是否已实测可利用造成危害
detection_channel: <inband|oob|timing|differential|cross_tool>
detected_by: mcpfuzz v2
discovered: <YYYY-MM-DD>
target_env: <测试环境，如 mcphub gateway /mcp/{server}，stdio in container>
---

# <标题：服务 + 漏洞一句话>

## 概述
<一句话：什么服务、什么工具参数、什么类型、能造成什么危害>

## 威胁模型
<边界说明：若经网关/容器部署，容器=该 MCP 的宿主，危害到容器即构成实害>

## 漏洞描述与根因
<数据如何流入危险操作、为什么成立>

## 检测方式
<mcpfuzz 用哪个通道、什么载荷、什么响应确认的>

## PoC（触发步骤）
<最小可复现的调用序列 + 载荷 + 关键输出>

## 可利用性证据
<逐条实测证据，敏感值脱敏>

## 影响
<攻击者/智能体能做什么，爆炸半径>

## 修复建议
<如何缓解>
