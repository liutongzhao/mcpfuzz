# MCP 黑盒检测 baseline 调研

> 面向作者本人。调研时间 2026-11-11。四份原始笔记在同目录 `../research_notes/MCP 黑盒检测 baseline 调研/`，带逐条引用。
> 我们的工作：纯黑盒检测 MCP 服务器的服务端注入漏洞（命令注入、参数注入、路径穿越、SSRF、代码注入）；方法＝语义参数分类 + 智能体序列构建 + 执行确认 oracle（带内回显 / 带外回连 / 时延 / 跨工具读回 + 差分对照）；数据集 44 正 / 24 负，召回 72.7% / 精确率 91.4%。

---

## 一、一句话结论

**"首个黑盒 MCP 服务端注入检测"这个说法已经不能用了。** 既有同行评审论文、也有开源工具在做几乎同一件事——对 MCP 工具参数真实发注入载荷、再看反应确认命中。但它们**没有一个**同时具备我们这三件事：按语义给参数分类（而不是对所有参数无差别喷载荷）、用智能体搭前置调用序列、以及在有 CVE 背书的数据集上报出精确率/召回率。所以新意要从"首个做这件事"**改成**"首个把语义推断 + 状态构建 + 执行确认组合成系统方法，并做了可信度量的黑盒工作"。

下面按威胁程度从高到低排。

---

## 二、必须正面处理的工作（和我们重叠、会被审稿人拿来问）

### 2.1 学术：Corvus（《Exposed by Design》）—— 黑盒动态，学术上最接近
- 出处：arXiv 2608.00150，单作者（Nicolás Padilla），2026-07-31，**预印本**，未标会议。
- 做法：34 个测试模块（13 静态 + 21 动态），覆盖 10 类 MCP 漏洞。对 414 个联网服务器做主动审计，发现 68 个可报告漏洞（SQL 注入、指向云 metadata 的 SSRF、路径穿越、prompt 模板注入等），68 个都拿到了 GHSA 编号。作者声称会开源。
- 和我们的区别（从摘要判断）：**它没有 LLM 语义参数分类，也没有前置调用序列构建**，是"按模块逐项检查"的思路。漏洞类别和我们高度重叠，Related Work 必须讲，若代码放出来，它是学术侧最该跑的同条件黑盒 baseline。

### 2.2 学术：MCPSafetyScanner —— VIPER 用过的黑盒 baseline
- 出处：arXiv 2504.03767（MCP Safety Audit），Leidos 团队。多智能体审计：一个 agent 探测服务器的 tools/prompts/resources，另一个 agent 查知识库里的相关漏洞并给修复建议。**它不靠真实执行确认**。
- 价值：VIPER-MCP 已经拿它当 baseline，测出误报率 43.1% / 漏报率 63.8%。它能直接对端点跑，是对我们最"公平"的学术黑盒 baseline 候选，而且它"不做执行确认→高误报"正好能衬托我们。代码据称在 `github.com/johnhalloran321/mcpSafetyScanner`（笔记里凭记忆，未核实）。

### 2.3 工具：mcpsnare —— 和我们设计最像的开源工具
- PyPI，MIT 许可，v0.5.0，2026-07-23 发布。
- **几乎就是我们的黑盒版**：覆盖命令注入、代码/eval 注入、SSRF、路径穿越（还有 SQLi、缺认证、信息泄露）；能钻进嵌套对象、数组元素、enum 受限参数、资源模板 URI；确认手段是 canary 回显、校准时延、基线差分、带外回连（本地或 interactsh），结果分 CONFIRMED / FIRM / TENTATIVE 三级；支持 stdio 和 streamable HTTP。
- 和我们的差距：**没有参数注入这一类，没有语义参数分类，没有多步序列构建**，是对参数无差别打载荷。
- 结论：**第一优先 baseline**。它覆盖我们四类、走 HTTP、正好对上我们网关的部署方式，可以直接跑 44/24 数据集。

### 2.4 工具：PortSwigger 官方 "MCP Server Scanner" Burp 扩展 —— 业界标准脸面
- 作者 Peter Hendy（PortSwigger 官方 BApp），v0.1.0，2026-06-30 更新。
- 做法：发现 tools/resources/prompts，构造带可注入点的 JSON-RPC 请求喂给 Burp 主动扫描器，对工具参数做**路径穿越 + 盲 RCE**（经 Burp Collaborator 带外确认），外加认证绕过、DNS rebinding、元数据泄密检查。
- 价值：审稿人一定认识 Burp。但它只覆盖 PT + 盲 RCE，且是图形界面驱动、不好批量脚本化。
- 结论：**建议作为"业界标准工具"baseline**，哪怕只能半自动跑一部分服务器。

### 2.5 工具：mcpsec、MCPwn —— 次级开源对照
- **mcpsec**（MIT，26 星）：运行时模式走 stdio/HTTP，带 138 条命令注入、104 条路径穿越、81 条 SSRF 载荷 + eval 探针，`--ai` 开关加 LLM 生成载荷。**README 没说清怎么确认命中**。声称 6 个 CVE 但只点名了 CVE-2026-35394。
- **MCPwn**（Go，AGPL，1 星）：良性探针确认——唯一标记回显、短 sleep、临时文件读回、SSRF 用 127.0.0.1 canary；支持 stdio/SSE/HTTP。
- 结论：可作为"开源 fuzzer"对照组，尤其 mcpsec 跑一次 `--ai` 开 / 关，能侧面说明"加 LLM 载荷"不等于"语义分类 + 序列构建"。

---

## 三、只放相关工作、不拉进同一张表硬比

### 3.1 需要源码的白盒 MCP 检测器（只能当"白盒上界"）
它们条件和我们不同（要源码、受语言限制），公平性上不能当同条件 baseline，只能在开源子集上作参照。

| 工作 | 出处 | 底座 | 规模 / 数字 |
|---|---|---|---|
| **VIPER-MCP** | arXiv 2605.21392，预印本 | CodeQL 污点 + LLM 动态 PoC | 39,884 仓库，106 个 0-day，67 个 CVE；FNR 7.7%（FPR 0% 还是 4.6% 两处来源冲突，须读 v2 核实） |
| **MCP-BiFlow** | arXiv 2605.07836，预印本 | YASA 双向污点 | 32 案例召回 93.8%；优于 CodeQL/Semgrep/Snyk/MCPScan |
| **MCPInspect** | arXiv 2510.16558，**DSN 2026**（唯一确认录用） | Semgrep 规则 | 67,057 服务器，标记 833 个有漏洞 |
| **mcp-sec-audit** | arXiv 2603.21641，预印本 | 模式匹配 + Docker/eBPF 沙箱 | 查"过权能力"，非具体注入；9 个 lab 服务器 |

VIPER 是唯一"检测 + 动态确认"都做的白盒工作，但它的确认靠插桩；**我们的线上执行确认 oracle 就是它的黑盒替代**，这是我们对它最硬的区分点。另外 VIPER **没有用任何通用 Web/REST 扫描器做 baseline**，这给我们留了"首个系统展示通用工具在 MCP 上失效"的空位。

### 3.2 方向相反的"描述级/投毒"扫描器
这些防的是"恶意服务器攻击 agent"，和我们"外部攻击者打有漏洞的服务器"方向正好反过来，不是公平对手：
- **Snyk Agent Scan**（原 Invariant mcp-scan，2025-06 被 Snyk 收购）：查工具描述投毒、shadowing、toxic flow，要 Snyk token。
- **Cisco mcp-scanner**：YARA + LLM + Cisco API；行为模式要读源码。独立测试里 27 条 YARA 告警只有 6 条是真问题。
- **Ramparts、Nova Proximity**：YARA / 规则 / 静态。
- **商业**（Enkrypt、Pillar、Lasso、Protect AI、SandboxAQ、NeuralTrust）：讲的是提示注入、PII、过权、治理，**都没点名命令注入 / 路径穿越 / SSRF**。
- **MCPGuard**（arXiv 2510.23673，PKU+腾讯）：基本是综述，无评测数字。

### 3.3 学术 Web 扫描器（移植不过来）
- **Witcher**（S&P 2023）、**Atropos**（USENIX Sec 2024）：灰盒，要插桩 PHP 解释器——违背我们纯黑盒威胁模型。
- **Black Widow**（S&P 2021）、**YuraScanner**（NDSS 2025）：依赖浏览器页面/表单，MCP 没有 UI，移植不了。
- 但它们的**评测范式值得借**：YuraScanner 复用 Black Widow 的 XSS 引擎、只比探索策略；Witcher 做 "BurpPlus"（把自己爬的请求喂给 Burp）隔离"爬取"和"检测"的贡献。我们可以照着把"序列构建"和"oracle"两个贡献分开量化（见第五节）。

### 3.4 REST API 测试里最像我们的：VOAPI2（必须在 Related Work 讲清区别）
- 出处：**USENIX Security 2024**，上海交大，开源在 `github.com/NSSL-SJTU/VoAPI2`。
- 做法：按接口功能和**参数名关键字**推断漏洞类型（例如 CWE-78 里 40% 的参数名含 cmd/command），用带外回连确认 SSRF/XSS/命令注入，用 SQLMap 测 SQLi。
- **这和我们"语义参数分类 + 带外 oracle"表面上太像了**，审稿人一定会提。区别要写死：VOAPI2 靠 **OpenAPI 规范 + 参数名关键字 + 规范里的生产者-消费者依赖**；我们只有自然语言描述的 JSON Schema，依赖只藏在描述里、没有规范，靠 **LLM 语义推断**（关键字匹配换个服务器就漏，这正是我们消融要打的点）。
- 其余 REST fuzzer（RESTler、EvoMaster 默认、Schemathesis、AutoRestTest、LlamaRestTest）的判定基本只看 HTTP 500，**确认不了注入**，安全向的只有 NAUTILUS（USENIX Sec'23，要人工标注规范）、VOAPI2、和 2026 年给 EvoMaster 新加的 SQLi 时延 / XSS 回显 oracle。

---

## 四、LLM agent / LLM-only 作为 baseline

这一类不是"现成工具对打"，而是审稿人必问的稻草人："**为什么不直接让大模型 / 渗透 agent 去找漏洞？**" 得主动把它做成 baseline 并打掉。

- **只看描述让 LLM 判断**：先例是 MCPSEC（arXiv 2609.10854，ASU）的 LLM baseline，召回 84.2%。但更有力的是这条可写进论文的论点——**修复版（负样本）和漏洞版的工具描述通常一模一样，只看描述原理上就分不出修没修**；再加 S&P 2024 那篇 SecLLMHolmes 的证据（LLM 判漏洞不稳定、把已修复代码判成有漏洞、改个空格就变卦）。
- **通用编程 agent 直接调工具找漏洞**：先例是《Baselines Before Architecture》（arXiv 2607.13085，2026-07）——裸 Codex/OpenCode 跑 XBOW 已能解很大一部分，建议论文必报同模型裸 agent baseline；BountyBench（NeurIPS 2025）也用 Claude Code/Codex，但"发现漏洞"任务成功率极低（≤12.5%，Claude Code ~5%）。
- **一个开源渗透 agent**（PentestGPT USENIX Sec'24 / CAI / Strix）接到 MCP 端点上。
- **共同话术支撑"必须执行确认"**：学界的漏洞发现基准（CVE-Bench、XBOW）清一色用外部判定器 / flag，不信 agent 自报；curl 在 2026-01 因为 AI 编造的漏洞报告直接关停了赏金。**这些都论证：agent 自报不可信，执行确认才是对的。**
- **一个顺带的贡献点**：目前没人定量比较过"agent 自报成功率 vs 真实结果"的差距。我们的 B2 baseline（裸 agent 同时按它自报、和按我们 oracle 计分）这个测量本身可以算一小块贡献。

---

## 五、Baseline 选型建议（分层）

**第一层·必比（同条件黑盒，直接跑 44/24）**
1. **mcpsnare** —— 做法最像、覆盖我们四类、走 HTTP。头号对手。
2. **MCPSafetyScanner** —— 学术黑盒、VIPER 用过、无执行确认→高误报，衬托我们。
3. **Corvus**（若开源）—— 学术上最接近的黑盒动态工作。

**第二层·建议比（衬托方法、回应质疑）**
4. **PortSwigger MCP Server Scanner（Burp）** —— 业界标准脸面。
5. **mcpsec 运行时（`--ai` 开/关）** —— 说明"加 LLM 载荷 ≠ 语义分类 + 序列构建"。
6. **通用工具经 mcpo 转接**：有现成的开源转接层 **mcpo**（Open WebUI 官方，MIT）能把 MCP 工具包装成 OpenAPI/HTTP，于是 ZAP 主动扫描 + OAST、RESTler、EvoMaster 黑盒都能跑 MCP。预期它们大面积失效（MCP 没有 URL/ID 层次，依赖推断废掉；工具报错多半不映射成 500，500-oracle 几乎零报）——**这个"失效"本身就是论文论点的实证**，照 VOAPI2 的"500 里真漏洞只占 2.5–5.4%"那样量化。用第三方 mcpo 而不是自己写 shim，能挡住"你故意把 baseline 做弱"的质疑。
7. **LLM-only baseline（B1）** 和 **裸 agent baseline（B2）** —— 见第四节。

**第三层·只放 Related Work**：VIPER-MCP / BiFlow / MCPInspect（白盒上界）、VOAPI2 / NAUTILUS（REST 近亲）、Witcher / Black Widow（范式借鉴）、Snyk/Cisco 等描述级扫描器（方向相反）。

**消融（学 RestTestGen+V / BurpPlus 的隔离思路）**：去语义分类（对所有参数打所有载荷）、去序列构建（只单步调用）、逐个去 oracle 通道（带外/时延/读回/差分）；再加一组"**baseline + 我们的序列与取值**"，把"序列构建"的增益单独隔出来。所有 baseline 一律折算成**服务器级二元**结果，在 44 正/24 负上比，和我们口径一致。

---

## 六、我们还站得住的差异化卖点

1. **参数注入（argument injection）这一类**：整个调研范围内，没有任何工具/论文单独把它当检测类别。
2. **语义参数分类**：所有现成工具都是对字符串/URI 参数无差别喷载荷；我们按语义先分类再定向打。
3. **智能体序列构建**：所有现成黑盒工具都没有——它们逐参数单请求，搭不起"先建状态再打深层工具"的前置链。这是我们和它们最硬的分水岭。
4. **有 CVE 背书的精确率/召回率**：现成的小工具（mcpsnare、mcpsec、MCPwn…）**没有一个报过精确率和召回率**；我们有 44/24 的可信数字。
5. **大规模黑盒测量**：配合执行确认，报"真正可利用"的流行率（MCPZoo 已证明静态告警真阳性不到 50%，静态流行率不可信——正好反衬我们）。

---

## 七、"首个"措辞的判断与推荐说法

- **不能说**："首个黑盒 / 动态检测 MCP 服务端注入的工具/方法"——mcpsnare、PortSwigger、mcpsec、MCPwn、Corvus 都会证伪。
- **可以说（择一，且都要配 Related Work 把上面这些列清楚）**：
  - "首个将**基于语义的参数分类、智能体前置序列构建、与多通道执行确认**整合为端到端黑盒方法的工作"；
  - "首个在**有 CVE 背书的数据集上给出精确率/召回率**的黑盒 MCP 服务端注入检测"；
  - "首个把**参数注入**纳入 MCP 服务端注入检测的工作"。
- 稳妥做法：正文不抢"首个"，把贡献写成"我们**识别出**现有 MCP 黑盒工具的三个共同缺陷（无差别喷载荷、无状态构建、无可信度量），并用一个整合方法解决"，novelty 落在"方法整合 + 可信度量 + 新类别"，不落在"第一个做动态检测"。

---

## 八、风险点与待核实事项

1. **工具重名**：GitHub 上已有至少两个叫 `mcpfuzz` 的项目（NAMAN-VERMA-02、8endit），我们工具也叫 mcpfuzz。**投稿前建议改名**，否则撞名、也不利检索区分。
2. **VIPER-MCP 的 FPR 冲突**：一处 0%、一处 4.6%，可能是 v1/v2 差异。引用前必须读 v2 PDF 核实，v2 是否标了会议也要确认。
3. **四大顶会录用情况**：本次检索**没找到** S&P/USENIX/CCS/NDSS 2025–2026 的 MCP 服务器论文，但这只是"没搜到"、不是确证——没直接翻会议录用列表。VIPER（浙大）、BiFlow（华科）、No-Box（ASU）、MCPZoo（复旦）都是顶会级团队的预印本，很可能正在审稿，应按 concurrent work 处理。投稿前逐个会议录核查。
4. **开源与可跑性待确认**：Corvus、MCPSafetyScanner、mcpsnare、BiFlow 的仓库地址和能否真跑，要落地验证后再定进不进 baseline。
5. **mcpo 行为待实测**：它是否把工具报错映射成 HTTP 500、是否代理 Resources API，README 没写明，本地起一个看 `/openapi.json` 就知道。
6. **新 CVE 数据集**：arXiv 2611.11104 收了"截至 2026-02 的 24 个已验证 MCP 漏洞（命令注入/RCE/路径穿越最多）"——和我们数据集可能有交集，值得比对去重。
7. **注入专用工具的 CLI 能力**（commix 时间盲注、SSRFmap、dotdotpwn、SSTImap）是凭先验写的，若要组"每类最强单点工具"组合基线，命令行细节得逐一核实。

---

*原始四份笔记（学术论文 / 扫描工具 / Web·REST fuzzer / 渗透 agent）在 `../research_notes/MCP 黑盒检测 baseline 调研/`，每条都有链接。*
