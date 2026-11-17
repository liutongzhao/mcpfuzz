# MCP 服务器安全学术文献目录（baseline / SOTA 定位），截至 2026-11-11

范围说明：本笔记只覆盖学术论文和 arXiv 预印本。"服务端代码漏洞"指 MCP 服务器实现中的 command/argument injection、path traversal、SSRF、code injection 等；"客户端/LLM 侧"指 tool poisoning、prompt injection、rug pull 等，攻击对象是 agent 或 LLM 的推理，不是服务器代码。凡没有找到会议录用说明的，一律按"预印本"处理。

## Q1. VIPER-MCP 具体做什么？还有哪些白盒/静态/污点分析的 MCP 服务器漏洞检测器？

### Takeaway
VIPER-MCP（arXiv 2605.21392，预印本，没有标注会议）是最强的白盒混合方法：先用 CodeQL 做污点分析，再用 LLM 驱动动态 PoC 确认。它扫描了 39,884 个仓库，报告 106 个 0-day、67 个 CVE。另外至少还有四个静态或混合的检测器，都需要源码：MCP-BiFlow（YASA 污点分析，召回 93.8%）、MCPInspect（Semgrep 规则，DSN 2026，这是唯一确认过会议录用的）、mcp-sec-audit（Python 模式匹配 + Docker/eBPF 模糊测试），以及 "MCP at First Glance" 里基于 SonarQube 的测量。

### Cited Findings
**VIPER-MCP**
- 标题："VIPER-MCP: Detecting and Exploiting Taint-Style Vulnerabilities in Model Context Protocol Servers"。作者：Pengyu Sun, Zifeng Kang, Qishu Jin, Enhao Huang, Xin Liu, Dakun Shen, Song Li。v1 2026-05-20，v2 2026-08-12，cs.CR，abs 页面没有 venue/comments 字段 — [arXiv abs](https://arxiv.org/abs/2605.21392)
- 自称"第一个端到端自动审计框架"，既检测 taint-style 缺陷，又生成具体的 PoC prompt 来确认可利用性。两项核心技术：(1) 两遍静态分析里加 anchor-query，把污点告警映射到具体 MCP tool handler，构造锚定漏洞的调用链；(2) 反馈驱动的 prompt 演化，用双变异器修正工具选择漂移、加深参数探索，再用 fitness 打分选种子 — [arXiv abs](https://arxiv.org/abs/2605.21392)
- 大规模结果：扫描 39,884 个开源 MCP 服务器仓库，发现 106 个 0-day，全部有端到端利用 trace，已分配 67 个 CVE — [arXiv abs](https://arxiv.org/abs/2605.21392)
- 支持 Python/JavaScript/TypeScript，聚焦三类 taint-style 漏洞（命令注入等）。二手来源称其 curated benchmark 上 FPR 4.6%、FNR 7.7%，优于 MCPSafetyScanner — [Moonlight 综述（二手）](https://www.themoonlight.io/en/review/viper-mcp-detecting-and-exploiting-taint-style-vulnerabilities-in-model-context-protocol-servers)；[skillsafe 博客（二手）](https://skillsafe-web-github.pages.dev/blog/viper-mcp-taint-scanning/)
- 数字冲突：项目内部的早期原文阅读记录（memory/related-work-viper-mcp.md）写的是 FPR 0%、FNR 7.7%（260 个服务器 = 130 vulnerable + 130 benign；baseline MCPSafetyScanner FPR 43.1%/FNR 63.8%，Cisco AI Defense 24.6%/73.1%；三类 = 命令注入/SSRF/路径穿越；产物在匿名仓 anonymous.4open.science/r/Viper-EA4D）。二手博客写 FPR 4.6%，可能是 v1 和 v2 的差别。引用前必须对照 v2 PDF 核实 — [arXiv PDF](https://arxiv.org/pdf/2605.21392)
- 代码：abs 页面没有给仓库链接 — [arXiv abs](https://arxiv.org/abs/2605.21392)

**MCP-BiFlow（"Unsafe by Flow"）**
- Xinyi Hou, Yanjie Zhao, Haoyu Wang（华科 Haoyu Wang 组），arXiv 2605.07836，cs.SE，2026-05-08，没有 venue — [arXiv abs](https://arxiv.org/abs/2605.07836)
- 双向静态分析：请求侧看攻击者可控参数流向敏感操作，返回侧看不可信或敏感数据流进 MCP 输出。方法是 MCP 感知的入口恢复 + 协议特定污点建模 + 过程间传播 — [arXiv abs](https://arxiv.org/abs/2605.07836)
- 在 32 个已确认 MCP 漏洞上找出 30 个（召回 93.8%），优于 CodeQL、Semgrep、Snyk Code、MCPScan。扫描 15,452 个仓库，得到 549 个候选簇，人工确认 87 个服务器中的 118 条漏洞路径 — [arXiv abs](https://arxiv.org/abs/2605.07836)
- 原型基于 YASA 静态分析框架 — [arXiv PDF](https://arxiv.org/pdf/2605.07836)
- 代码：abs 页面没有链接 — [arXiv abs](https://arxiv.org/abs/2605.07836)

**MCPInspect（"A First Look at the Security Issues in the MCP Ecosystem"）**
- Xiaofan Li, Xing Gao。arXiv 2510.16558，v1 2025-10-18，v2 2026-04-27，**已录用 DSN 2026**（标题和匿名投稿版不同）— [arXiv abs](https://arxiv.org/abs/2510.16558)
- 跨实体研究（registry/host/server），覆盖 6 个公开 registry 共 67,057 个服务器。MCPInspect 是集成前的分析工具，检测误导性工具元数据和可利用的代码漏洞，标记出 833 个有漏洞的服务器、18 个可疑描述 — [arXiv abs](https://arxiv.org/abs/2510.16558)
- 基于 Semgrep 规则；人工核查了 mcp.so 上 377 个被标记服务器中的 41 个（来自搜索摘要，未逐字核对 PDF）— [arXiv PDF](https://arxiv.org/pdf/2510.16558)
- 论文观点：代码层缺陷（如 code injection）"不是必需的"，但能把攻击者可控参数变成 exploit — [arXiv abs](https://arxiv.org/abs/2510.16558)

**mcp-sec-audit（"Auditing MCP Servers for Over-Privileged Tool Capabilities"）**
- Charoes Huang, Xin Huang, Amin Milani Fard，arXiv 2603.21641，2026-03-23，cs.CR/cs.SE，没有 venue — [arXiv abs](https://arxiv.org/abs/2603.21641)
- 静态部分：对 Python MCP 服务器做模式匹配。动态部分：Docker 沙箱模糊测试 + eBPF 监控。检测方式是基于规则识别"过权能力"（文件系统/网络/命令执行），不是具体注入漏洞 — [arXiv abs](https://arxiv.org/abs/2603.21641)
- 在 Vulnerable MCP Servers Lab 上，动态分析覆盖 9/9 个服务器且与语言无关，静态分析只覆盖 Python 服务器 — [arXiv HTML](https://arxiv.org/html/2603.21641v1)

**MCP at First Glance**
- "Model Context Protocol (MCP) at First Glance: Studying the Security and Maintainability of MCP Servers"，arXiv 2506.13538。对 1,899 个开源 MCP 服务器做混合静态分析（SonarQube 等）。报告约 7.2% 的服务器有安全问题，凭据暴露最常见，官方服务器没发现问题；作者呼吁 MCP 专用的检测技术 — [arXiv HTML v2](https://arxiv.org/html/2506.13538v2)

**其他相关（静态或风险评估）**
- MCP-in-SoS：开源 MCP 服务器风险评估框架，以静态为主，集成了 Cisco AI Defense MCP Scanner 等，arXiv 2603.10194 — [arXiv PDF](https://arxiv.org/pdf/2603.10194)
- "What Happens Locally, Leaks Globally"：检测 MCP 服务器隐私泄露风险，arXiv 2606.21338（只看到标题）— [arXiv PDF](https://arxiv.org/pdf/2606.21338)
- "Mitigating Taint-Style Vulnerabilities in MCP Servers via Security-Aware Tool Descriptions"，arXiv 2607.07461，是防御而不是检测（只看到标题）— [HF papers](https://huggingface.co/papers/2607.07461.md)

### Inferences
- 白盒或静态这条线已经有至少 4 个工具，污点分析底座有三种：CodeQL（VIPER）、YASA（BiFlow）、Semgrep（MCPInspect）。它们都需要源码、受语言限制，无法测闭源或只暴露远程端点的服务器。这正是纯黑盒方法的定位空间。
- VIPER-MCP 是唯一同时做"检测 + 动态确认"的工作，但它的确认依赖 instrumentation。我们的线上（wire-level）执行确认 oracle 是它的黑盒替代。
- 公平的 baseline 对比：VIPER 和 BiFlow 需要源码，只能在开源子集上做"白盒上界"对比，不能当同条件 baseline。BiFlow 论文里的 CodeQL/Semgrep/Snyk Code 对比也可以借鉴。
- 我们查到的所有工作里，没有一项单独把 argument injection（参数注入）作为检测类别。这一点只基于摘要级阅读，没有对每篇全文逐一核实。

### Gaps
- VIPER-MCP 的 FPR 是 0% 还是 4.6%，以及 v2 是否标注了 venue，需要读 v2 PDF 核实。
- BiFlow、MCPInspect、mcp-sec-audit 的代码是否开源、能否运行，abs 页面都没有说明，需要查 PDF 里的 artifact 声明。

## Q2. 有没有黑盒、动态或 fuzzing 的 MCP 服务器检测方法？

### Takeaway
有，但很少，也不完全对标我们。和我们最接近的黑盒动态工作是 "Exposed by Design"（Corvus，单作者预印本，2026-07）：对 414 个联网 MCP 服务器做主动测试，发现 SQLi/SSRF/路径穿越等 68 个漏洞。另外有 MCP Safety Audit 的 McpSafetyScanner（多 agent 探测，被 VIPER 当作 baseline）、mcp-sec-audit 的动态沙箱 fuzzing（需要能在本地部署）、MCPZoo（把仓库转成可运行服务，再评估 8 个现有扫描器）。No-Box/MCPSEC 只看描述，目标是间接提示注入，不是服务端代码漏洞。

### Cited Findings
**Exposed by Design / Corvus**
- Nicolás Padilla（单作者），arXiv 2608.00150，2026-07-31，13 页，cs.CR/cs.AI，没有 venue — [arXiv abs](https://arxiv.org/abs/2608.00150)
- 从 11 个数据源被动发现服务器（crt.sh、HuggingFace、GitHub、npm、Smithery、PyPI、Censys、FOFA、Shodan、glama.ai、pulsemcp）。Corvus 有 34 个测试模块，覆盖 10 类 MCP 特定漏洞。2026 年 7 月做了 4 轮测量，确认 640 个生产服务器，动态审计 414 个，发现 68 个可报告漏洞（SQL 注入、指向云 metadata 的 SSRF、prompt template 注入、经 cursor 操纵的路径穿越）。91.8% 没有 OAuth，687 个工具实例无访问控制地暴露 shell 执行，41.6% 的服务器三天内消失。作者声称会开源 Corvus — [arXiv abs](https://arxiv.org/abs/2608.00150)
- 34 个模块里 13 个是静态的（分析元数据/manifest/schema），21 个是动态的（与活的端点交互），包含协议 fuzzing 模块（MCP05）和 rug-pull 签名比对。68 个漏洞获得 GHSA 登记 — [arXiv PDF](https://arxiv.org/pdf/2608.00150)
- 二手摘要称其中 38 个服务器有 CRITICAL 级命令注入（只来自搜索摘要，没有在原文核对）— [arXiv PDF](https://arxiv.org/pdf/2608.00150)

**MCP Safety Audit / McpSafetyScanner**
- "MCP Safety Audit: LLMs with the Model Context Protocol Allow Major Security Exploits"，arXiv 2504.03767（作者应为 Radosevich & Halloran，凭记忆，本次没有核实）。McpSafetyScanner 是多 agent 工具："hacker" agent 探测服务器的 tools/prompts/resources，另一个 agent 检索知识库里的相关漏洞并给出修复建议 — [arXiv HTML v2](https://arxiv.org/html/2504.03767v2)
- 它被 VIPER-MCP 用作 baseline（项目内原文阅读记录：FPR 43.1%/FNR 63.8%）— [VIPER arXiv PDF](https://arxiv.org/pdf/2605.21392)

**MCPGuard（2510.23673）**
- Bin Wang 等 9 人，arXiv 2510.23673，2025-10-27，没有 venue。摘要列出三类威胁：协议设计缺陷导致的 agent hijacking、MCP 服务器中的传统 Web 漏洞（注入/XSS/不安全反序列化、远程部署的弱认证）、供应链风险。摘要没有定量结果，更像综述加防御分类；检测方法是静态还是动态，摘要没说 — [arXiv abs](https://arxiv.org/abs/2510.23673)

**No-Box / MCPSEC**
- Zehua Zhang, ..., Yan Shoshitaishvili, Tiffany Bao, Ruoyu Wang, Adam Doupé（ASU SEFCOM 组，16 人），arXiv 2609.10854，v1 2026-09-09，v2 2026-09-16，没有 venue — [arXiv abs](https://arxiv.org/abs/2609.10854)
- 只用注册时暴露的工具元数据，审计**间接提示注入**。在 20 个服务器、177 个工具上，人工确认 95 个有漏洞；MCPSEC 标记 143 个，命中 94 个（召回 98.9%），LLM baseline 是 80 个（84.2%）。没有执行确认，本质是"假设性"漏洞 — [arXiv abs](https://arxiv.org/abs/2609.10854)

**MCPZoo / Rethinking MCP Security**
- Pei Chen, ..., Xudong Pan, Jiarun Dai, Min Yang（复旦），arXiv 2607.11086，2026-07-13，18 页，扩展自 3 页的 MCPZoo 数据集论文（arXiv 2512.15144）— [arXiv abs](https://arxiv.org/abs/2607.11086)
- 用多 agent 框架把静态仓库转成可运行服务，并通过真实协议交互验证。共 64,611 个唯一服务器（总计 113,927 个），其中超过 37,288 个支持动态分析。现有扫描器把 96.89% 的服务器标为有风险，但人工验证显示被抽样告警中真阳性不到 50%，各扫描器的结论也互不一致。作者提供公开的风险查询接口 — [arXiv abs](https://arxiv.org/abs/2607.11086)
- 搜索摘要称评估了 8 个安全扫描器（abs 没写数量）— [arXiv HTML](https://arxiv.org/html/2607.11086)

**非学术工具**
- fuzzd（GitHub，ksek87）：MCP 协议 fuzzer，标记崩溃、挂起、畸形 JSON-RPC 响应，不是论文 — [GitHub](https://github.com/ksek87/fuzzd)

### Inferences
- 真正"纯黑盒 + 服务端注入 + 执行确认"的学术工作，目前只有 Corvus 部分重叠。它是单作者预印本，按模块做检查，看起来没有 LLM 参数语义分类，也没有前置调用序列构建。不过它的 SSRF/路径穿越/SQLi 发现与我们的类别重叠，必须正面讨论；如果代码开源，它是最贴近同条件的黑盒 baseline。
- McpSafetyScanner 能直接对端点运行，已被 VIPER 用作 baseline，是对我们最"公平"的黑盒 baseline 候选。MCPZoo 评估的 8 个扫描器也可以作为 baseline 池参考。
- No-Box 是"只看描述"的极端版本，可作为对照，说明描述级推断（无执行）会带来高误报（143 个标记中只有 94 个是真的）。我们可以借此论证执行确认的价值，但它的漏洞类别不同（IPI）。
- MCPZoo 的"扫描器告警真阳性不到 50%"可以直接支撑我们"需要执行确认 oracle"的动机。

### Gaps
- Corvus、McpSafetyScanner 的仓库地址和可运行性没有核实。
- 本次没有找到其他 LLM agent 驱动的 MCP 服务器 fuzzing 学术论文。软件工程会议（ICSE/FSE/ASE/ISSTA 2026）上是否有，也没能直接查会议录。

## Q3. 哪些论文对 MCP 生态做了大规模测量？发现了什么？

### Takeaway
测量类工作已经很多，规模从 1,360 到 67,057 个服务器不等。它们给出的漏洞流行率口径差别很大，有的是静态告警，有的是"能力暴露"，彼此不能直接比较。没有一个权威的"服务端注入流行率"数字。

### Cited Findings
- MCPInspect / First Look（DSN 2026）：6 个 registry 共 67,057 个服务器，存在广泛的 registry 劫持和调用操纵条件，833 个有漏洞的服务器，18 个可疑描述 — [arXiv abs](https://arxiv.org/abs/2510.16558)
- MCPZoo：64,611 个唯一服务器，超过 37,288 个能动态运行；扫描器标记 96.89% 有风险，但真阳性不到 50% — [arXiv abs](https://arxiv.org/abs/2607.11086)
- VIPER-MCP：39,884 个仓库，106 个 0-day，67 个 CVE — [arXiv abs](https://arxiv.org/abs/2605.21392)
- MCP-BiFlow：15,452 个仓库，87 个服务器中确认 118 条漏洞路径 — [arXiv abs](https://arxiv.org/abs/2605.07836)
- Exposed by Design：联网服务器中确认 640 个、审计 414 个；68 个漏洞，91.8% 没有 OAuth，687 个 shell 执行工具没有访问控制，41.6% 三天内消失。摘要还提到公网可检测到超过 21,000 个 MCP 服务器实例 — [arXiv abs](https://arxiv.org/abs/2608.00150)
- Parasites in the Toolchain（arXiv 2509.06572）：1,360 个服务器、12,230 个工具，8.7% 的工具、27.2% 的服务器暴露可利用能力；主题是寄生式工具链攻击（数字来自搜索摘要）— [arXiv HTML v4](https://arxiv.org/html/2509.06572v4)
- MCP at First Glance：1,899 个服务器，约 7.2% 有安全问题 — [arXiv HTML v2](https://arxiv.org/html/2506.13538v2)
- "Same Name, Different Server: A Security Census of Silent Drift in the MCP Ecosystem"（arXiv 2609.14119）：普查了 21,643 个服务器，主题是同名服务器漂移（只看到搜索摘要）— [arXiv PDF](https://arxiv.org/pdf/2609.14119)
- "Give Them an Inch...: Caller Identity Confusion in MCP-Based AI Systems"（arXiv 2603.07473），主题是认证/身份（只看到标题）— [arXiv PDF](https://arxiv.org/pdf/2603.07473)
- "An Empirical Study of Model Context Protocol Applications"（arXiv 2607.25635，只看到标题）— [arXiv PDF](https://arxiv.org/pdf/2607.25635)
- Connor（"From Component Manipulation to System Compromise: Understanding and Detecting Malicious MCP Servers"，arXiv 2604.01905）：检测**恶意**服务器（不是有漏洞的服务器），用行为偏离分析，在 1,672 个市场服务器中发现 2 个恶意服务器 — [arXiv HTML v2](https://arxiv.org/html/2604.01905v2)

### Inferences
- 我们的测量贡献如果要算新意，需要强调"黑盒 + 执行确认"的流行率，也就是真正可利用的漏洞，而不是静态告警或能力暴露。MCPZoo 的"真阳性不到 50%"正好说明静态流行率不可信。
- Corvus 的 41.6% 三天消失率提示：联网测量要说明快照时间和服务器流失。

### Gaps
- Parasites in the Toolchain 和 MCP at First Glance 的 venue 没有核实（First Glance 可能已在某个 SE 会议或期刊发表，未确认）。

## Q4. 有哪些有漏洞 MCP 服务器的 benchmark/数据集？

### Takeaway
专门针对服务端代码漏洞的公开 benchmark 很少：BiFlow 的 32 个案例、VIPER 的 260 个服务器（130+130）、Vulnerable MCP Servers Lab（9 个）。大多数 benchmark（MCPTox、MCPSecBench）面向 agent 或客户端攻击。

### Cited Findings
- MCPTox：建在 45 个真实活跃 MCP 服务器、353 个工具之上，测 tool poisoning。arXiv 2508.14925；后续引用给出的 venue 是 AAAI 2026（DOI 10.1609/aaai.v40i42.40895）。测试用例数在不同版本里是 1348 或 1312 — [arXiv abs](https://arxiv.org/abs/2508.14925)；[Semantic Scholar](https://www.semanticscholar.org/paper/MCPTox:-A-Benchmark-for-Tool-Poisoning-Attack-on-Wang-Gao/34df7d82136868e5d492968647efd17d442a6720)
- MCPSecBench："A Systematic Security Benchmark and Playground for Testing Model Context Protocols"，arXiv 2508.13220，venue 未确认，面向 agent/客户端/协议多层攻击 — [arXiv PDF](https://arxiv.org/pdf/2508.13220)
- MCP Pitfall Lab：暴露开发者在多向量攻击下的 MCP 工具服务器安全陷阱，arXiv 2604.21477（只看到标题）— [arXiv PDF](https://arxiv.org/pdf/2604.21477)
- Vulnerable MCP Servers Lab（9 个服务器）被 mcp-sec-audit 用作评测集 — [arXiv HTML](https://arxiv.org/html/2603.21641v1)
- BiFlow：32 个已确认 MCP 漏洞案例 — [arXiv abs](https://arxiv.org/abs/2605.07836)
- MCPZoo：64,611 个服务器，超过 37,288 个可运行，是动态分析的底座数据集 — [arXiv abs](https://arxiv.org/abs/2607.11086)
- "From Tool Connection to Execution Control: Benchmarking Security Invariants in MCP-Style Agent Runtimes"（arXiv 2606.29073，只看到标题，是 runtime 侧）— [arXiv PDF](https://arxiv.org/pdf/2606.29073)

### Inferences
- VIPER 的 63 个已有 CVE 和 BiFlow 的 32 个案例，可以与我们的 44 正/24 负数据集取交集，做重叠对比。MCPZoo 可以作为扩大规模的服务器来源。

### Gaps
- BiFlow 和 VIPER 的 benchmark 是否公开、具体有哪些 CVE，没有核实。

## Q5. 四大安全顶会（S&P/USENIX Sec/CCS/NDSS）2025–2026 有没有 MCP 相关工作？

### Takeaway
本次检索**没有找到**任何在四大安全顶会录用的 MCP 服务器安全论文（多次搜索都没有命中会议录或 dblp 条目）。已确认录用的同行评审 MCP 安全工作有：DSN 2026（MCPInspect）、AAAI 2026（MCPTox）、ACM TOSEM（MCP Landscape 综述）。其余都是预印本。

### Cited Findings
- 多次搜索都没有返回四大会议的 MCP 论文录用页 — [搜索结果之一：arXiv 2606.28690 等](https://arxiv.org/pdf/2606.28690)
- DSN 2026：A First Look at the Security Issues in the MCP Ecosystem — [arXiv abs](https://arxiv.org/abs/2510.16558)
- AAAI 2026：MCPTox — [Semantic Scholar](https://www.semanticscholar.org/paper/MCPTox:-A-Benchmark-for-Tool-Poisoning-Attack-on-Wang-Gao/34df7d82136868e5d492968647efd17d442a6720)
- ACM TOSEM：Model Context Protocol (MCP): Landscape, Security Threats, and Future Research Directions（Hou et al.，arXiv 版是 2503.23278，作者对应关系凭记忆），列出的出版日期是 2026-09-16 — [ACM DL](https://dl.acm.org/doi/10.1145/3796519)
- 其他预印本（防御、综述、协议）：SoK "Security and Safety in the MCP Ecosystem"（arXiv 2512.08290）、MCP-DPT 防御放置分类（2604.07551）、CASCADE（2604.17125）、Attested Tool-Server Admission（2605.24248）、Formal Security Analysis of Agent Protocol Composition（2606.28690）、Labels Are Not Endpoints（2608.12880）、Enterprise-Grade Security for MCP（2504.08623）、MindGuard（2508.20412）、SMCP（2602.01129）、AEGIS（2608.20481）、MCP Tool Poisoning in Agentic AI Frameworks（2611.03555）、When MCP Servers Attack（2509.24272）— [SoK](https://arxiv.org/pdf/2512.08290)；[MCP-DPT](https://arxiv.org/pdf/2604.07551)；[CASCADE](https://arxiv.org/pdf/2604.17125)；[Attested](https://arxiv.org/pdf/2605.24248)；[Formal](https://arxiv.org/pdf/2606.28690)；[Labels](https://arxiv.org/pdf/2608.12880)；[Enterprise](https://arxiv.org/pdf/2504.08623)；[MindGuard](https://arxiv.org/pdf/2508.20412)；[SMCP](https://arxiv.org/pdf/2602.01129)；[AEGIS](https://arxiv.org/pdf/2608.20481)；[Tool Poisoning cross-framework](https://arxiv.org/html/2611.03555)；[When MCP Servers Attack](https://arxiv.org/pdf/2509.24272)
- 非学术：NSA 发布的 MCP Security Design 信息表（2026-06）— [defense.gov PDF](https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF)

### Inferences
- VIPER（浙大）、BiFlow（华科）、No-Box（ASU）、MCPZoo（复旦）都是顶会级团队的预印本，很可能正在四大会议审稿。S&P 投稿应把它们当作 concurrent work 引用并区分。

### Gaps
- 没有直接访问 dblp、USENIX Security 2026、CCS 2026、NDSS 2026 的 accepted papers 页面，所以"四大会议没有 MCP 服务器论文"只是检索未命中，不是确证。投稿前需要逐个会议录核查。
- 本次没有核实 MCP-Guard（不同于 MCPGuard）、MCPLIB 的存在和 venue。

---

### 汇总表：作为 baseline 的适用性

| 工作 | ID / Venue | 盒型 | 目标 | 类别 | 规模/数字 | 代码 | 能否作同条件 baseline |
|---|---|---|---|---|---|---|---|
| VIPER-MCP | 2605.21392 预印本 | 白盒混合（CodeQL+动态） | 服务端注入 | CMDi/SSRF/PT | 39,884 仓库，106 个 0-day，67 个 CVE；FNR 7.7%（FPR 是 0% 还是 4.6% 有冲突） | 匿名仓（据项目记录） | 否，需要源码；可作开源子集上的白盒上界 |
| MCP-BiFlow | 2605.07836 预印本 | 白盒静态（YASA） | 服务端流 + 返回侧 | 污点类 | 32 个案例召回 93.8%；15,452 仓库中确认 118 条路径 | 未知 | 否，需要源码 |
| MCPInspect | 2510.16558 DSN'26 | 静态（Semgrep）+ 元数据 | 代码漏洞 + 误导元数据 | 代码注入等 | 67,057 个服务器，833 个有漏洞 | 未知 | 否，需要源码 |
| mcp-sec-audit | 2603.21641 预印本 | 静态 + 沙箱 fuzzing | 过权能力 | 能力风险 | 9 个服务器的 lab | 未知 | 弱，需要本地部署 |
| MCP at First Glance | 2506.13538 | 静态（SonarQube） | 测量 | 通用 | 1,899 个服务器，7.2% 有问题 | — | 否 |
| Exposed by Design / Corvus | 2608.00150 预印本 | **黑盒动态** | 服务端 + 认证 + 配置 | SQLi/SSRF/PT/CMDi 等 | 审计 414 个，68 个漏洞 | 声称开源 | **是，最接近** |
| McpSafetyScanner | 2504.03767 预印本 | 黑盒 agent 探测 | 综合 | 多类 | VIPER 测得 FPR 43.1%/FNR 63.8% | 有（PyPI，凭记忆，未核实） | **是** |
| MCPZoo | 2607.11086 预印本 | 动态底座 + 扫描器评估 | 测量 | 依扫描器而定 | 64,611 个服务器；告警真阳性不到 50% | 查询接口 | 是数据集来源，不是检测器 |
| No-Box / MCPSEC | 2609.10854 预印本 | 无盒（只看描述） | 间接提示注入 | IPI | 20 个服务器/177 个工具，召回 98.9% | 未知 | 否，类别不同 |
| MCPGuard | 2510.23673 预印本 | 未明 | Web 漏洞/劫持/供应链 | 综述 | 无定量 | 无 | 否 |
| Connor | 2604.01905 预印本 | 行为分析 | 恶意服务器 | 恶意 | 1,672 个中发现 2 个 | 未知 | 否 |
| MCPTox | 2508.14925 AAAI'26 | — | tool poisoning（客户端） | TP | 45 个服务器，353 个工具 | 未知 | 否 |
| MCPSecBench | 2508.13220 预印本 | — | agent/协议 | 多层 | — | 未知 | 否 |
