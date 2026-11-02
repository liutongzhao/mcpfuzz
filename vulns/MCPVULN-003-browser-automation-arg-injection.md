---
id: MCPVULN-003
mcp_service: mcp-server-browser-automation
mcp_version: 0.2.4
mcp_package: "@mindstone/mcp-server-browser-automation@0.2.4"
source: npm
tool: browser_get_text
param: ref
vuln_type: argument_injection
cwe: CWE-88
severity: medium
status: confirmed
confirmed_exploitable: partial
detection_channel: differential
detected_by: mcpfuzz v2
discovered: 2026-11-01
target_env: "mcphub gateway /mcp/io.github.mindstone_mcp-server-browser-automation（stdio 跑在网关容器内）"
---

# 漏洞说明：browser-automation 的 browser_get_text 参数注入（agent-browser CLI 标志注入）

| 项 | 内容 |
|---|---|
| 组件 | `@mindstone/mcp-server-browser-automation@0.2.4`（经 mcphub 网关以 stdio 接入） |
| 端点 | `http://<gateway>:3000/mcp/io.github.mindstone_mcp-server-browser-automation` |
| 工具/参数 | `browser_get_text.ref`（注入点，检测器自动定位） |
| 类型 | 参数注入 / CLI 选项注入（CWE-88） |
| 严重程度 | **中（Medium）** —— 参数注入已坐实；因底层用 `execFile` 无 shell，未坐实升级到 RCE/任意文件读写 |
| 发现方式 | mcpfuzz 黑盒检测，差分通道命中（`ref=--version` 使响应回显 `agent-browser 0.33.2`） |

## 1. 这个 MCP 是什么

`@mindstone/mcp-server-browser-automation` 是浏览器自动化 MCP：让智能体控制真实浏览器——导航、点击、填表、截图、读页面文本、管理标签页（21 个工具）。底层把每个动作转交给命令行工具 **`agent-browser`** 去驱动浏览器。出问题的 `browser_get_text` 自我描述为 *"Get the text content of the page (or of a single element)"*——**人设是"只读页面文本"，不应能操纵底层 CLI**。

## 2. 根因（真实源码）

`dist/tools/observation.js` 把用户可控的 `ref` 直接作为位置参数塞进 CLI argv：
```js
const selector = args.ref ?? 'body';
const result = await execAgentBrowser(['get', 'text', selector]);   // → agent-browser get text <ref>
```
`dist/browser-client.js` 用 `execFile`（无 shell）执行：
```js
// execFile is safe against command injection (no shell interpretation)
const result = await execFileAsync(file, fileArgs, {...});
```

**开发者对了一半、错了一半：**
- ✅ 用 `execFile`（argv 数组、不经 shell）→ **命令注入被挡住**：`;`、`$()`、管道都是字面量，不会执行（已实测确认，容器内无命令落地）。
- ❌ 但把用户可控的 `selector` 当位置参数传入时**未加 `--` 分隔符**。CLI 解析器把以 `-` 开头的值（如 `--version`）当作**选项标志**解释 → **参数注入（CWE-88）**。

## 3. 实测证据

```
ref = "--version"   → 响应: agent-browser 0.33.2                    （版本号被 CLI 解析并回显）
ref = "--help"      → 响应: agent-browser get - Retrieve information ... Usage: agent-browser get <subcommand> [args] ...
ref = "; id > /tmp/x"  → 未执行（Chrome 127 无关报错），容器内无 /tmp/x    （证明无 shell，非命令注入）
ref = "$(id > /tmp/y)" → 同上，未执行
```
即 `ref` 确实流入 `agent-browser` 的 argv 并被当作标志解析（参数注入成立），但**不经 shell**（命令注入不成立）。

## 4. 影响（Impact）—— 诚实的危害边界

- **已坐实**：调用方能操纵传给 `agent-browser get` 的 CLI 标志。一个"读页面文本"的工具被用来执行 CLI 的其它功能（如 `--version`/`--help`，以及 agent-browser `get` 子命令支持的其它标志）。
- **危害上限**：因无 shell，**不能**执行任意系统命令。真实危害取决于 `agent-browser` 的标志面——若其存在 `--output <文件>`/`--config <文件>` 等能读写任意路径的标志，可能升级为任意文件读/写；**目前仅验证到 `--version`/`--help`，尚未坐实文件读写或 RCE**（待办：枚举 `agent-browser get` 标志面）。
- 因此严重度定为**中**。本条的主要价值在于**漏洞类型多样性**（证明黑盒检测能发现命令注入之外的注入类别），而非危害规模。

## 5. 可利用性论证（威胁模型）

同 [MCPVULN-002](MCPVULN-002-omni-mcp-server-rce.md) §5b：能力契约被打破（"读页面文本"工具不应能控 CLI 标志）即构成漏洞，与 stdio/HTTP 传输无关；远程/托管部署下有明确远程攻击者；本地部署下可经"智能体处理不可信页面内容 → ref 被污染"的路径到达。区别仅在**危害规模**：本条因无 shell 而受限。

## 6. 复现（最小命令）

```bash
python - <<'PY'
from mcpfuzz.driver import call_tool_sync
S="io.github.mindstone_mcp-server-browser-automation"
U=f"http://127.0.0.1:3000/mcp/{S}"
print(call_tool_sync(U, f"{S}-browser_get_text", {"ref":"--version"})["text"])  # → agent-browser 0.33.2
PY
```

## 7. 修复建议

- 传位置参数前加 **`--` 分隔符**阻止后续值被解析为标志：`execAgentBrowser(['get','text','--', selector])`；
- 或对 `ref` 做白名单校验（只允许 `@eN` 元素引用 / 合法 CSS 选择器，拒绝以 `-` 开头的值）。
