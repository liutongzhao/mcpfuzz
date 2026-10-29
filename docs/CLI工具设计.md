# MCPFuzz CLI 工具设计方案

> 目标：把 `prototype/` 从"一组脚本"升级成一个成体系的黑盒检测 CLI（对标 RESTler / nuclei 的使用体感）——命令行启动、单个与批量检测、参数体系完整、日志可追溯、检测过程实时滚动输出。
>
> 本文只定设计，不改代码。实现分阶段见文末里程碑。

---

## 1. 设计原则

1. **检测内核不动**：`driver / catalog / sink / payload / orchestrator / oracle` 六个模块的逻辑保持不变，CLI 只是它们的"外壳 + 编排 + 呈现"。
2. **事件驱动的输出**：内核不再直接 `print()`，而是**发事件**；由外壳决定渲染成"实时彩色界面 / 纯文本日志 / JSONL 机器流"。这是同时满足「好看的实时输出」和「完整可追溯日志」的关键解耦。
3. **一次运行 = 一个产物目录**：每次扫描落到独立目录，含人读日志、机读事件流、中间产物、最终报告，服务于论文的**可复现性**。
4. **配置可分层**：命令行参数 > 环境变量 > 配置文件 > 内置默认，层层覆盖。
5. **依赖极简**：只引入 `rich`（实时渲染）一个新依赖；参数解析用标准库 `argparse`。研究工具越少依赖越易复现。

---

## 2. 命令结构

命令名 `mcpfuzz`（包已叫 `mcpfuzz`），采用子命令制：

| 子命令 | 作用 | 对应现状 |
|---|---|---|
| `mcpfuzz scan` | **主命令**：完整检测（连接→推 sink→编排攻击→判定→报告），支持单个/批量 | `run_detect.py` |
| `mcpfuzz recon` | 侦察（dry-run）：连接+列工具+推 sink+出计划，**不发任何载荷**，预览攻击面 | `dump_catalog.py` + `dump_sinks.py` |
| `mcpfuzz report` | 把已有 `findings.json` 重新渲染成表格 / Markdown | 无 |
| `mcpfuzz selftest` | 判定器 / 载荷合成自检 | `selftest_oracle.py` / `selftest_payload.py` |

`recon` 是黑盒工具的好习惯：先看清攻击面和将要发的计划，再决定是否开火（尤其面向第三方服务器时的伦理前置）。

---

## 3. 参数体系（以 `scan` 为主）

### 3.1 目标指定
```
mcpfuzz scan <target>...                 # 一个或多个目标，依次检测
  <target> 可为：
    - 直连 URL：http://host:port/mcp
    - mcpServers 配置文件：servers.json（复用 targetcfg.resolve_target）
  --name NAME            从配置文件里选指定 server（默认取第一个）
  --all                  配置文件里的所有 server 全测（批量）
  --batch FILE           批量清单文件（每行一个 URL，或一个 mcpServers 配置）
  --header "K: V"        临时追加 HTTP 头（可重复），如鉴权；不写进日志明文
```
单目标与批量走**同一条路径**：批量 = 对目标列表循环，每个独立产物目录，末尾出汇总表；默认**错误不中断**（`--fail-fast` 可改）。

### 3.2 检测范围
```
  --tool NAME            只测这些工具（可重复，调试用）
  --exclude-tool NAME    排除工具（可重复）
  --sink TYPE[,TYPE]     只测这些 sink 类型（command_injection/argument_injection/path_traversal/ssrf…）
  --max-payloads N       每个参数最多发 N 条载荷（控量/限速）
```

### 3.3 大模型开关（对应消融实验 RQ3）
```
  --no-llm-sink          sink 推断只用规则（关大模型）
  --no-llm-plan          编排只用兜底计划（长度 1，schema 填值）
  --llm-model NAME       覆盖模型（默认 swe-2-high）
  --llm-workers N        sink 推断并发（默认 6）
```

### 3.4 判定 / 网络（把当前硬编码项提成参数）
```
  --oob-callback URL     OOB 回连基址（默认 env MCP_OOB_CALLBACK / 43.133.80.249:9100）
  --oob-query URL        OOB 命中查询地址
  --poll-rounds N        OOB 回收轮数（当前硬编码 3）
  --poll-interval SEC    回收间隔（当前硬编码 2.0）
  --timeout SEC          单次工具调用超时
  --retries N            连接/调用重试次数
  --delay SEC            每次工具调用之间的间隔（礼貌限速，防 DoS）
```

### 3.5 输出 / 日志
```
  -o, --out-dir DIR      产物根目录（默认 runs/）
  --run-name NAME        本次运行名（默认 <时间戳>__<server-slug>）
  --format rich|plain|json   控制台呈现：彩色实时 / 纯文本行 / JSONL（默认 rich；非 TTY 自动降级 plain）
  -v, --verbose          更详细（-vv 打印每条载荷 / LLM 交互）
  -q, --quiet            只出最终结论
  --report md|json|both  最终报告格式（默认 both）
  --no-cache             不读写 sink/plan 缓存（消融/重测用）
```

### 3.6 安全 / 伦理
```
  --dry-run              等价于 recon：只预览攻击面，不发载荷
  --yes                  跳过"即将对目标发起带副作用的检测"确认（批量/CI 必备）
```
非 `--yes` 且目标非自建靶机时，开火前打印一条确认（载荷含回连/写文件等真实副作用，呼应方案第 10 节伦理）。

### 3.7 配置文件（免重复输入）
支持 `--config mcpfuzz.toml`，把常用项固化成 profile：
```toml
[oob]
callback = "http://43.133.80.249:9100"
query    = "http://43.133.80.249:9100/__hits"
[llm]
model = "swe-2-high"; workers = 6
[scan]
poll_rounds = 3; poll_interval = 2.0; out_dir = "runs"
```
优先级：命令行 > 环境变量 > 配置文件 > 默认。LLM 的 key/base_url 仍留在 `llm_config.py`（已 gitignore），不进通用配置。

---

## 4. 实时终端输出（体验核心）

### 4.1 技术选型
**`rich`** 的 `Live` 显示。理由：pip 一个包、无需全屏接管终端、能同时跑进度条 + 滚动日志 + 表格，输出可被 `--format plain` 一键降级为纯文本行（管道/CI/写文件时自动切换）。`textual`（全屏 TUI）对一次性扫描过重，不采用。

### 4.2 扫描中的界面
顶部固定状态区（随进度刷新）+ 下方滚动事件日志；**确认漏洞一出现就以红色醒目插入**：
```
 MCPFuzz ▸ cyanheads/git-mcp-server 2.1.4   http://43.133.80.249:8080/mcp

 阶段  [3/4] 攻击编排
 工具  ████████████░░░░░░  7/11   git_add
 载荷  已发送 142    OOB 待回收 8
 结果  ● 确认 2   疑似无 5   未触达 1

 ── 实时日志 ──────────────────────────────────────────
 12:30:01  连接成功  协议 2025-06-18  工具 11 个
 12:30:03  [sink] git_add.files → argument_injection (high, rule+llm)
 12:30:11  [plan] git_show: 1 步（参数自洽，无需前置工具）
 12:30:12  [attack] git_add.files ← 发射 6 条载荷
 12:30:15  ● 确认  git_add.files   argument_injection / oob
             载荷  `curl http://43.133.80.249:9100/mcpf8c37eb`
             证据  GET /mcpf8c37eb  来自 43.133.80.249  (curl/7.88.1)
```
结束时清掉 Live，打印**结论表** + 报告路径。`-vv` 时日志区额外显示每条载荷与 LLM 往返。

### 4.3 三种 `--format`
- `rich`（默认，TTY）：上面的实时界面。
- `plain`（非 TTY 自动）：同样的事件，逐行带时间戳输出，无重绘，适合 `tee`、CI、`> log`。
- `json`：每个事件一行 JSON 到 stdout，供外部程序消费。

---

## 5. 日志与产物

每次 `scan` 生成独立目录，并维护 `runs/latest` 软链指向最近一次：
```
runs/20261029-123000__git-mcp-server/
  run.log         # 人读全量日志（时间戳 + 级别；-vv 含工具调用参数、LLM 往返）
  events.jsonl    # 机读事件流（每行一个事件，见 §6），可复现与离线分析的主载体
  catalog.json    # 解析后的工具清单
  sinks.json      # 每参数的 sink 标注
  findings.json   # 最终结论（现有结构不变）
  report.md       # 人读报告（确认漏洞 + 载荷 + 证据 + 可复现序列）
  .sink_cache/ .plan_cache/   # 复用现有缓存
批量时另有顶层：
  runs/20261029-123000__batch/batch_summary.{json,md}   # 各目标一行汇总
```
**日志安全**：鉴权头、LLM API key 一律脱敏（`Authorization: ***`）。`run.log` 始终写全量（不受 `-q` 影响，`-q` 只压控制台）；`events.jsonl` 始终写，是复现实验的事实来源。

---

## 6. 事件模型（内核与呈现的接口）

内核各模块接收一个 `reporter.emit(event)` 回调，替换现有 `print()`。一套事件同时驱动：实时界面、`run.log`、`events.jsonl`。事件类型（草案）：

| 事件 | 载荷要点 |
|---|---|
| `run.start` / `run.end` | 目标、配置快照 / 时长、各状态计数 |
| `connect.ok` / `connect.fail` | 协议版本、工具数 / 错误 |
| `sink.labeled` | tool、param、sinks、来源(rule/llm/both)、置信度 |
| `plan.made` | tool、步数、reachable、note |
| `launchpad.fail` | tool、未触达原因（前置报错 / 取值失败） |
| `attack.param.start` | tool、param、载荷条数 |
| `payload.sent` | tool、param、channel（仅 `-vv`） |
| `finding.confirmed` | tool、param、sink、channel、载荷、证据、复现序列 |
| `finding.clean` / `finding.unreached` | tool、param、note |
| `report.saved` | 产物路径 |

机读 `events.jsonl` 顺带解决论文可复现性：一次运行可完整回放。

---

## 7. 代码结构调整

内核模块基本不动，新增一个 `cli` 外壳层：
```
prototype/
  mcpfuzz/
    cli/
      main.py        # argparse 子命令、参数解析、分发
      console.py     # rich 渲染（Live 布局、结论表、主题、plain/json 降级）
      events.py      # 事件类型 + Reporter（扇出到 console / run.log / events.jsonl）
    config.py        # Settings 数据类：合并 flags/env/file，优先级与校验
    run.py           # 单目标扫描编排 = 薄层，串起现有六模块并 emit 事件（取代 run_detect.main）
    driver.py / catalog.py / sink/ / payload/ / orchestrator/ / oracle/   # 仅把 print() 改为 reporter.emit()
  pyproject.toml     # [project.scripts] mcpfuzz = "mcpfuzz.cli.main:main"；声明 rich 依赖
```
改造要点：
- `Orchestrator`、`executor.run_tool`、`SinkInferencer` 增加可选 `reporter` 参数；现有 `print(...)` → `reporter.emit(...)`。无 reporter 时静默（保持可库用）。
- `Oracle(...)` 的 OOB 地址、`poll_window`、driver 的 `timeout/retries` 从 `Settings` 注入，不再硬编码/读环境变量。
- `run_detect.py` 保留为薄封装或移除，功能并入 `mcpfuzz scan`。

安装后即可 `mcpfuzz scan ...`（`pip install -e prototype/`）。

---

## 8. 典型用法

```bash
# 单目标，默认实时界面
mcpfuzz scan http://43.133.80.249:8080/mcp

# 配置文件里的某个 server，带鉴权，只测两个工具，详细输出
mcpfuzz scan servers.json --name lucky --header "Authorization: Bearer xxx" \
        --tool git_add --tool git_show -v

# 先侦察攻击面（不发载荷）
mcpfuzz recon http://host/mcp

# 批量，跳过确认，错误不中断，写到指定目录
mcpfuzz scan --batch targets.txt --yes -o runs/benchmark

# 消融：关大模型 sink 推断，禁用缓存（配合 RQ3）
mcpfuzz scan http://host/mcp --no-llm-sink --no-cache

# 管道/CI：纯文本事件流
mcpfuzz scan http://host/mcp --format plain --yes | tee scan.log
```

---

## 9. 实现里程碑

| 阶段 | 内容 | 完成标志 |
|---|---|---|
| C0 骨架 | `cli/main.py` argparse + `scan` 子命令 + `config.py`；跑通等价于现 `run_detect` | `mcpfuzz scan URL` 与旧脚本结果一致 |
| C1 事件化 | `events.py` + Reporter；内核 `print()` 全改 emit；落 `run.log` + `events.jsonl` | 产物目录成形，日志完整可追溯 |
| C2 实时界面 | `console.py` rich Live；`--format rich/plain/json`、`-v/-q` | 扫描过程实时滚动、确认漏洞醒目 |
| C3 批量与侦察 | 多目标/`--batch`/`--all` + 汇总表；`recon`/`--dry-run` | 一条命令跑完基准集出汇总 |
| C4 打磨 | `report`/`selftest` 子命令、`--config`、脱敏、`--yes` 确认、`pyproject` 入口 | `pip install -e` 后全功能可用 |

---

## 10. 待定（需你拍板）

1. **命令名**：`mcpfuzz`（跟包名）是否合适，还是另起一个更"产品化"的名字。
2. **报告格式**：Markdown 之外，论文阶段是否要直接出 LaTeX 表 / CSV（便于填召回率表）。
3. **批量汇总**：是否需要跨运行的"总账"（一个累积 DB/CSV，汇总历次扫描的所有确认漏洞，便于 RQ2 零日统计）。
