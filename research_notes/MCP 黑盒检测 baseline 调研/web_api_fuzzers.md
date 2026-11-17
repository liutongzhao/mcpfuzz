# 通用 Web / REST API 漏洞扫描器与 Fuzzer 作为 MCP 黑盒检测的"改造基线"调研（截至 2026-11）

> 说明：标【已核实】的条目是本次会话读过原文（PDF 正文或会议页）的；标【未核实/凭先验】的是调研员已有知识，本次没有找到一手来源确认，写作时须再查 dblp。

## Q1. REST API fuzzer：哪些能检测注入类安全漏洞，哪些只报 500？

### Takeaway
主流 REST fuzzer（RESTler、RestTestGen、MINER、Morest、EvoMaster 默认配置、Schemathesis 以及 LLM 类的 AutoRestTest/LlamaRestTest）的 oracle 基本只看 500/schema 违规，**不能直接确认注入**；面向安全的只有 NAUTILUS（USENIX Sec'23）、VOAPI2（USENIX Sec'24）以及 2026 年给 EvoMaster 加的 SQLi(时延)/XSS(回显) oracle。其中 **VOAPI2 和我们的方法最像**（按接口功能推断漏洞类型 + 带外回连验证），是最该引用/对比的工作。

### Cited Findings
**NAUTILUS（USENIX Security 2023，Deng et al.）【已核实】**
- 32nd USENIX Security，pp.5593–5609；核心是对 OpenAPI 规范做"注解"（编码操作关系和参数生成策略），黑盒、需要 OAS — [USENIX 页](https://www.usenix.org/conference/usenixsecurity23/presentation/deng-gelei)
- 在 6 个服务上平均多检出 141% 漏洞、多覆盖 104% 操作；9 个真实服务上 23 个 0-day、12 个 CVE（含 Confluence RCE）— [USENIX 页](https://www.usenix.org/conference/usenixsecurity23/presentation/deng-gelei)
- 需要测试者**手工标注** OpenAPI schema — [Sahin/Zhang/Arcuri arXiv 2604.00702](https://arxiv.org/html/2604.00702v1)
- Oracle 三类：状态码变化（如登录绕过返回 200）、响应数据结构偏离 OAS（如 SQLi 返回额外表内容）、"语义关系"（如 payload `1+1` 响应 `2`，用于命令/代码执行）— [论文 PDF §4.4.2](https://usenix.org/system/files/usenixsecurity23-deng-gelei.pdf)
- 基线 4 个：ZAP（用 OpenAPI add-on、关掉爬虫）、w3af（`crawl.open_api` 模块）、RESTler、Morest。**改造方式：所有工具统一使用 FuzzDB payload 字典；ZAP/w3af 把字典更新到对应模块；RESTler/Morest 改其变异模块让取值来自字典而非随机值，但不改其序列生成策略** — [论文 PDF §5.1](https://usenix.org/system/files/usenixsecurity23-deng-gelei.pdf)
- 论文原话理由：漏洞扫描器能报漏洞，而"RESTful API test tools aim to achieve better coverage and bug reporting, and they do not have vulnerability reporting capability"，所以选"可扩展自定义 payload"的工具以便公平 — [论文 PDF §5.1](https://usenix.org/system/files/usenixsecurity23-deng-gelei.pdf)
- 结果：所有基线表现相近（同字典、逐端点测）；ZAP/w3af 因内置 XSS 执行检测略好于两个 REST fuzzer；NAUTILUS 在三个教学基准上平均多 69.8%；三个真实应用 NAUTILUS 10 个 0-day vs 基线合计 3 个 — [论文 PDF §5.2](https://usenix.org/system/files/usenixsecurity23-deng-gelei.pdf)
- 项目页（是否开源未在 PDF 中明确）：[sites.google.com/view/nautilus-testing](https://sites.google.com/view/nautilus-testing)

**VOAPI2（USENIX Security 2024，Du et al.，上海交大）【已核实】**
- "Vulnerability-oriented Testing for RESTful APIs"，33rd USENIX Security pp.739–755 — [USENIX 页](https://www.usenix.org/conference/usenixsecurity24/presentation/du)；[dblp](https://dblp1.uni-trier.de/rec/conf/uss/DuLW00ZHWX24.html)
- 核心观察：接口隐藏的漏洞类型与接口**功能**强相关；统计 CVE 发现如 CWE-22 中 52%(16/31) 参数名含 path/dir/file，CWE-78 中 40%(22/55) 含 CMD/command/system，CWE-89 中 53%(37/70) 含 SQL/database/select — [论文 PDF Table 1](https://usenix.org/system/files/usenixsecurity24-du.pdf)
- 覆盖 SSRF、XSS、路径穿越、SQLi、命令注入、任意上传；按 API 类型配 corpus：资源请求 API→`http://IP:PORT/ssrf/{0}`；路径处理 API→`/etc/passwd`；系统配置 API→`curl http://IP:PORT/command/{0}`；数据库 API→`1" or "1"="1` + 集成 SQLMap；文本展示 API→`<img src='http://IP:PORT/xss/{0}'>` — [论文 PDF Table 3、§3.4](https://usenix.org/system/files/usenixsecurity24-du.pdf)
- Oracle：SSRF/XSS/命令注入用**带外 Validation Server**（收到回连即判漏洞）；其余类型基于响应判断 — [论文 PDF §3.4.2](https://usenix.org/system/files/usenixsecurity24-du.pdf)
- 实现基于 RESTler 扩展（复用 RESTler Compile 模块，改其测试 corpus）— [论文 PDF §4](https://usenix.org/system/files/usenixsecurity24-du.pdf)
- 基线 5 个：ZAP（用其 resolver 解析 API 规范）、Astra（REST API 扫描器）、RESTler、RestTestGen、MINER；全部默认配置、各 5 小时；**明确不把 5xx 当漏洞**，只计真实安全漏洞 — [论文 PDF §5.1](https://usenix.org/system/files/usenixsecurity24-du.pdf)
- 结果：VOAPI2 共 26 个漏洞（7 个 0-day + 19 个已知，4 个 CVE）；ZAP/Astra 在 Gitea、Rbaskets、GitLab 零检出；三个 REST fuzzer 主要找到 500，人工分析 500 中真正是漏洞的比例仅 5.4%(RESTler)、3%(MINER)、2.5%(RestTestGen)，且"需要手动插入 payload 才能验证"；还做了 "RestTestGen+V"（给基线加上 VOAPI2 的漏洞导向策略）变体 — [论文 PDF §5.2、Table 5](https://usenix.org/system/files/usenixsecurity24-du.pdf)
- 论文总结两类基线失败原因：REST fuzzer 缺漏洞 corpus、漏洞不导致 500 就漏；扫描器（ZAP）不能构造满足数据依赖的多请求序列 — [论文 PDF §5.2](https://usenix.org/system/files/usenixsecurity24-du.pdf)
- 精度：ZAP/Astra 判 XSS 只看 payload 是否出现在响应里，对大量无展示功能的 API 产生误报；VOAPI2 FDR 更低 — [论文 PDF §5.3](https://usenix.org/system/files/usenixsecurity24-du.pdf)
- 开源：[github.com/NSSL-SJTU/VoAPI2](https://github.com/NSSL-SJTU/VoAPI2)

**EvoMaster 安全 oracle（arXiv 2604.00702，2026-04，Sahin/Zhang/Arcuri）【已核实，预印本】**
- 论文称 REST fuzzer 最常见的 oracle 就是检测 server error，fuzzer 通常按覆盖率和 500 数比较 — [arXiv 2604.00702](https://arxiv.org/html/2604.00702v1)
- 在 EvoMaster 中加入 fuzzing 后的"security testing 阶段"：SQLi 用**时延 oracle**（对 <2s 的 2xx 端点注入 `' OR SLEEP(5)-- -` 等 16 个 payload，>5s 判漏洞）；XSS 用**回显 oracle**（反射型看 2xx 响应中未转义 payload；存储型 POST/PUT/PATCH 后 GET 读回）；payload 来自 Big List of Naughty Strings — [arXiv 2604.00702](https://arxiv.org/html/2604.00702v1)
- 评估 52 个 API：9 个人造、8 个 vulnerable-by-design（黑盒）、36 个 WFD 语料（白盒）— [arXiv 2604.00702](https://arxiv.org/html/2604.00702v1)
- 该文对其他工具的归纳：RESTler 有 4 条安全规则（如删除后不可访问、用户命名空间隔离）；VoAPI2 做 SSRF/XSS/命令注入；APIF 用 SecLists 攻击（XSS/SQLi/SSRF）但不能处理 OpenAPI、需反代抓真实流量；RestTestGen 扩展可测 mass assignment；对 Schemathesis、RESTest 等未描述安全 oracle — [arXiv 2604.00702](https://arxiv.org/html/2604.00702v1)
- EvoMaster 支持 REST/GraphQL/RPC，黑盒和白盒两种模式 — [EvoMaster tool report（BUAA 索引）](https://research.buaa.edu.cn/en/publications/tool-report-evomasterblack-and-white-box-search-based-fuzzing-for/)

**LLM 类 REST 测试工具（功能测试，非安全）**
- AutoRestTest：ICSE 2025 Research Track，Kim/Stennett/Sinha/Orso，MARL + 语义属性依赖图(SPDG) + LLM 生成输入 — [ICSE 2025 页](https://conf.researchr.org/details/icse-2025/icse-2025-research-track/112/A-Multi-Agent-Approach-for-REST-API-Testing-with-Semantic-Graphs-and-LLM-Driven-Input)；另有 ICSE 2025 Companion 工具论文 — [ACM DL](https://dl.acm.org/doi/10.1109/ICSE-Companion66252.2025.00015)；参加了 SBFT 2026 工具竞赛 — [arXiv 2607.01063](https://arxiv.org/html/2607.01063v1)
- LlamaRestTest：FSE 2025 Research Papers（用小模型）— [FSE 2025 页](https://conf.researchr.org/details/fse-2025/fse-2025-research-papers/51/LlamaRestTest-Effective-REST-API-Testing-with-Small-Language-Models)
- ARAT-RL：被 AutoRestTest 引为 "Adaptive REST API testing with reinforcement learning, ASE 2023" — [AutoRestTest arXiv 2411.07098](https://arxiv.org/pdf/2411.07098)
- RESTGPT：AutoRestTest 中描述为用 LLM 从自然语言描述中提取规则、生成示例参数值；推测对应 ICSE-NIER 2024 "Leveraging large language models to improve REST API testing"（**推断，未直接核实**）— [AutoRestTest arXiv 2411.07098](https://arxiv.org/pdf/2411.07098)
- MASTEST（arXiv 2511.18038）：LLM 多智能体 REST 测试 — [arXiv](https://arxiv.org/html/2511.18038)
- 其他 LLM 安全向 REST 测试多为小 venue/学位论文：CISIS 2024 用 LLM 从 OpenAPI 生成注入/BOLA/mass assignment 测试 — [cosa.cunbm](https://cosa.cunbm.utcluj.ro/?p=100848)；TU Wien 2025 硕士论文（GPT-4o-mini 测 NoSQLi 等）— [repositum](https://repositum.tuwien.at/bitstream/20.500.12708/216474/1/Strauss%20Diana%20-%202025%20-%20Automating%20Software%20and%20Vulnerability%20Testing%20in%20REST..pdf)

### Inferences
- 对审稿人可这样定位：REST fuzzer = "解决序列/依赖与合法取值，但 oracle 是 500"；扫描器 = "有注入 payload 和 oracle，但不会构造依赖序列"；我们 = 两者都要、且 MCP 没有 OpenAPI 和形式化依赖。这正是 VOAPI2 §5.2 的论证结构，可以直接借鉴。
- VOAPI2 的"按接口功能（参数名关键字）推断漏洞类型 + 带外回连"与我们的"LLM 语义参数分类 + OOB oracle"高度相似，**必须在 Related Work 明确区分**：VOAPI2 依赖 OpenAPI + 参数名关键字匹配 + 规范中的生产者-消费者依赖；我们面对的是只有自然语言描述的 JSON Schema，依赖只在描述里，靠 LLM 推断。
- AutoRestTest/LlamaRestTest 的 oracle 是 500，作为安全基线意义不大，但可作为"LLM 生成参数值/序列"这一子模块的对比参照（只比覆盖或"成功调用率"）。

### Gaps
- 以下 venue 凭先验、本次未核实：RESTler（ICSE 2019）、Schemathesis（ICSE 2022）、RESTest（ISSTA 2021 tool demo）、RestTestGen（ICST 2020）、Morest（ICSE 2022）、MINER（USENIX Sec 2023?）、Golmohammadi et al. REST API 测试综述（TOSEM 2023/2024）。写作前请在 dblp 核实。
- ARAT-RL 只有二手引用确认 ASE 2023；RESTGPT 的 ICSE-NIER 2024 是推断。
- 未找到 NAUTILUS 代码明确开源的证据。

## Q2. 通用 Web 漏洞扫描器（学术 + 工业）

### Takeaway
学术扫描器（Black Widow、Witcher、Atropos、YuraScanner）都绑定"浏览器页面/表单/PHP 解释器"，对 MCP 这种无 UI、非 PHP 的 JSON-RPC 服务几乎不可移植；它们的价值主要在于**评估方法论**——尤其是"固定 oracle、只比探索策略"的做法。工业扫描器（ZAP、Burp、w3af）能吃 OpenAPI，是 REST 安全论文最常用的扫描器基线。

### Cited Findings
- **Witcher（IEEE S&P 2023，Trickel et al.）【已核实】**：灰盒、基于 AFL 的覆盖引导变异 fuzzing，检测 SQLi 和命令注入；oracle 是 "Fault Escalator"——改 dash shell（3 行）把解析错误升级为 segfault，用 LD_PRELOAD hook `recv()` 把 SQL 语法错误升级为 segfault；需插桩解释器/字节码（灰盒）— [Witcher 论文页](https://adamdoupe.com/publications/witcher-oakland2023.md)
- Witcher 基线：Burp（两种配置：单独 Burp，以及喂入 Witcher 爬取请求的 "BurpPlus"）、Black Widow、WebFuzz；ZAP/Arachni/w3af 只在相关工作中出现，引用 Black Widow 的结论间接覆盖 — [Witcher 论文页](https://adamdoupe.com/publications/witcher-oakland2023.md)
- Witcher 结果：已知漏洞 23/36（63.9%）；67 个新漏洞（65 SQLi + 2 命令注入），4 个 CVE；9 个 PHP 应用上 Burp 17 个 vs Witcher 70 个（52 个独有）；吞吐 142.1 req/s vs WebFuzz 22.5、Burp 6.8、Black Widow 1.6 — [Witcher 论文页](https://adamdoupe.com/publications/witcher-oakland2023.md)
- **Black Widow（IEEE S&P 2021，Eriksson et al.，Chalmers）**：黑盒数据驱动 web 扫描（导航建模 + 跨页面污点追踪），主攻 XSS — [论文 PDF](https://www.cse.chalmers.se/~andrei/bw21.pdf)；YuraScanner 指出其在先前评估中优于 Arachni、EotS、jÄk、Skipfish、w3af、ZAP — [YuraScanner PDF](https://www.ndss-symposium.org/wp-content/uploads/2025-388-paper.pdf)
- **YuraScanner（NDSS 2025，Stafeev et al.，CISPA）【已核实】**：LLM 驱动的任务导向 web 扫描（LLM 规划用户任务以到达深层状态）；**直接复用 Black Widow 的 XSS 检测引擎**（payload 调用唯一 id 的 `xss(id)` oracle 函数），只比探索策略；基线 Black Widow、BFS、Random BFS；12 个 0-day XSS vs Black Widow 3 个 — [NDSS 2025 PDF](https://www.ndss-symposium.org/wp-content/uploads/2025-388-paper.pdf)
- **Atropos（USENIX Security 2024，Güler et al.，CISPA）**：基于快照、反馈驱动的 PHP web 应用 fuzzing，针对服务端漏洞；平均多发现至少 32% bug、测试集上零误报 — [USENIX 页](https://www.usenix.org/conference/usenixsecurity24/presentation/g%C3%BCler)；代码 [CISPA-SysSec/atropos-legacy](https://github.com/CISPA-SysSec/atropos-legacy)；PHUZZ 称其只支持 PHP 7（hook 解释器底层 C 函数）— [PHUZZ arXiv 2406.06261](https://arxiv.org/pdf/2406.06261)
- **PHUZZ（arXiv 2406.06261）**：覆盖引导 PHP fuzzer，称识别 99% 漏洞，优于黑盒扫描器 Burp、ZAP、Wapiti、WFuzz — [arXiv](https://arxiv.org/pdf/2406.06261)
- **ZAP / w3af 用于 REST 的配置先例**：NAUTILUS 用 ZAP OpenAPI add-on 并关闭爬虫、w3af 用 `crawl.open_api` — [NAUTILUS PDF](https://usenix.org/system/files/usenixsecurity23-deng-gelei.pdf)；VOAPI2 用 ZAP 的 resolver 解析 API 规范 — [VOAPI2 PDF](https://usenix.org/system/files/usenixsecurity24-du.pdf)
- 其他第三方评测指出 ZAP、Burp Pro 漏掉大量注入、ZAP 缺 SSTI 检测 — [MDPI Electronics 11(13):2049](https://www.mdpi.com/2079-9292/11/13/2049)（非顶会，仅作背景）
- SpiderSapien（arXiv 2609.02532）：客户端爬虫+扫描器，用 LLM 处理表单输入校验，9 个应用；venue 未知 — [arXiv](https://arxiv.org/pdf/2609.02532)

### Inferences
- **最可行的扫描器基线是 ZAP（Active Scan + OpenAPI 导入）**，前提是有 MCP→OpenAPI 的转接层（见 Q4）。ZAP 内置命令注入、路径穿越、SSRF（需 OAST add-on/外部回连）、SSTI/代码注入规则，正好对齐我们的 5 类中的大部分。Burp Pro 是商业软件，可用但复现性差。
- Witcher/Atropos 需要插桩 PHP 解释器或灰盒信息，违背我们的纯黑盒威胁模型，**不适合做基线，只放 Related Work**；但 Witcher 的"把解析错误升级成崩溃"可在讨论 oracle 时作对照（我们不能插桩服务端）。
- YuraScanner 和 NAUTILUS 的"把 oracle/payload 固定、只比较探索/序列策略"是很好的范式：我们可以把**自己的执行确认 oracle 接到基线的序列生成上**（或者反过来，把基线的 payload 喂给我们的序列构建），从而把"序列构建"和"oracle"两个贡献分开量化。
- Black Widow 依赖浏览器 UI 导航，MCP 没有页面，**不可移植**。

### Gaps
- 没有核实 Black Widow 的具体会议元数据页（只有作者 PDF）和是否开源。
- 未读 Atropos 全文中的基线名单（片段未显示 Witcher 是否为基线）。
- 未找到 2025–2026 年 S&P/USENIX/CCS 上"LLM agent 对比 ZAP/Burp"的服务端注入扫描论文；YuraScanner 是最接近的（但只测 XSS）。

## Q3. 注入专用工具（sqlmap、commix、SSRFmap、dotdotpwn、tplmap/SSTImap、Interactsh）能否经 HTTP shim 指向 MCP 工具参数？

### Takeaway
可以，而且技术上最简单：这些工具都以"一个 HTTP 请求 + 标注的注入点"为输入，只要把某个 MCP 工具的某个参数暴露成 HTTP 请求里的一个字段即可。顶会先例中 VOAPI2 已把 SQLMap 集成进自己的 pipeline 作为 SQLi 检测器。它们的局限是：逐参数单请求、不会构建前置调用序列、不会产生合法的兄弟参数值。

### Cited Findings
- VOAPI2 把 SQLMap 集成进 Test Case Generator 以判断 SQLi — [VOAPI2 PDF §3.4.1](https://usenix.org/system/files/usenixsecurity24-du.pdf)
- NAUTILUS 和 VOAPI2 都引用了 sqlmap（NAUTILUS 文献键 `cite.sqlmap`）— [NAUTILUS PDF](https://usenix.org/system/files/usenixsecurity23-deng-gelei.pdf)
- 已有 MCP 专用 payload 扫描器：mcpsec（PyPI）称有 OS 命令注入扫描器，138 个 payload — [PyPI mcpsec](https://pypi.org/project/mcpsec/)；mcpfuzz（8endit）通过 `tools/call` 对每个工具执行构造的 payload — [GitHub 8endit/mcpfuzz](https://github.com/8endit/mcpfuzz)；mcp-server-fuzzer / PyPI `mcp-fuzzer`（Agent-Hellboy，MIT）做工具参数 fuzzing 和协议类型 fuzzing，多传输 — [PyPI mcp-fuzzer](https://pypi.org/project/mcp-fuzzer/)；fuzzd（ksek87）stdio 上 schema 扫描与 live audit — [GitHub ksek87/fuzzd](https://github.com/ksek87/fuzzd)。（均为 README/包页信息，未核实代码与效果）

### Inferences
- 可行改造方案：mcpo（或自写 30 行 FastAPI 网关）把 `tools/call name=X` 暴露为 `POST /X`、JSON body = arguments；然后
  - 命令注入：commix 的 `--data` + `*` 标注注入点（commix 支持时间盲注与文件写入型检测）；
  - SQLi：sqlmap `-r req.txt`（我们当前不支持 SQLi，可不做）；
  - 路径穿越：dotdotpwn 的 HTTP 模式或 ZAP 的 Path Traversal 规则；
  - SSRF：SSRFmap 或 ZAP + OAST（Interactsh）；
  - 代码/模板注入：SSTImap（tplmap 已不维护）。
  这些作为"每类最强单点工具"组合基线（"Injection-tool ensemble"）能回答审稿人"为什么不直接用 commix/sqlmap"的质疑。
- 关键公平性问题：这些工具对其他必填参数只能用固定种子值，且无法构建前置调用（如先 `create_project` 再 `run_in_project`）。建议做两档：(a) 基线原生（兄弟参数用 schema 默认/示例值）；(b) 基线 + 我们的序列/取值（给它最好的上下文），以隔离"payload/oracle"与"序列构建"的贡献——与 NAUTILUS"只换 payload 不改序列"、VOAPI2 的 "RestTestGen+V" 同一思路。
- 以上工具的具体 CLI 能力（commix 时间盲注、SSRFmap 模块、dotdotpwn HTTP 模式、SSTImap）**本次未逐一抓取官方文档核实**，是凭先验，写作前需核对。

### Gaps
- 未找到任何论文实际用 commix / SSRFmap / dotdotpwn / SSTImap 对 MCP 做过实验。
- Interactsh / Burp Collaborator 的文档本次未抓取。

## Q4. 是否已有把 MCP 工具暴露为 HTTP/OpenAPI 的适配器？

### Takeaway
有，而且成熟：Open WebUI 官方的 **mcpo**（MIT）把任意 MCP 服务器（stdio/SSE/streamable-HTTP）代理成 OpenAPI HTTP 服务，每个工具一个路由并自动生成 OpenAPI 文档。这让 ZAP（OpenAPI 导入）、RESTler、EvoMaster 黑盒、Schemathesis 原则上可直接跑在 MCP 上——可以作为"现成转接、零定制"的改造基线，降低"基线是你故意做弱"的质疑。

### Cited Findings
- mcpo：Open WebUI 项目的开源 MCP-to-OpenAPI 代理，MIT 许可，pip/uvx/Docker（`ghcr.io/open-webui/mcpo:main`）运行；可用 Claude Desktop 格式 config 同时代理多个服务器 — [搜索汇总/PyPI](https://pypi.org/project/mcpo/0.0.17/)；[Open WebUI 文档](https://docs.openwebui.com/features/extensibility/plugin/tools/openapi-servers/mcp.md)
- 每个工具一个路由（如 `/memory`、`/time`），为每个工具自动生成 OpenAPI schema，交互文档在 `/docs`，每工具文档在 `/<tool>/docs`；传输：stdio（默认）、`--server-type sse`、`--server-type streamable-http`；OAuth 2.1 仅 streamable-http — [GitHub open-webui/mcpo](https://github.com/open-webui/mcpo)
- 社区问答称 mcpo 不代理 MCP Resources API（需对照仓库核实）— [Augment MCP 页](https://www.augmentcode.com/mcp/mcpo-mcp-to-openapi-proxy)
- VIPER-MCP 的漏洞数据集中出现 `getsimpletool/mcpo-simple-server` 的路径穿越 CVE（说明 mcpo 类代理本身也是 MCP 生态的一部分）— [VIPER-MCP arXiv 2605.21392](https://arxiv.org/pdf/2605.21392)

### Inferences
- mcpo 生成的 OpenAPI 只有单个 POST 端点 + JSON Schema 请求体，**没有资源路径层次、没有 producer-consumer 依赖**（MCP 依赖只在自然语言描述里），所以 RESTler/EvoMaster 的依赖推断基本失效、退化为"逐端点随机/字典 fuzz"。这正好可作为论文论点的实证：现有工具的依赖推断建立在 REST 的 URL/ID 约定之上，在 MCP 上无用武之地。
- mcpo 的错误返回（工具 isError 是否映射为 HTTP 500 等）README 未写明；若工具异常不变成 500，RESTler/EvoMaster/Schemathesis 的 500 oracle 会几乎零报——需要实测并在论文中如实说明（这本身就是"500 oracle 对 MCP 无效"的证据）。
- 我们已有 mcphub 网关（见项目记忆），也可以自己写最薄的 HTTP shim，但**用第三方现成的 mcpo 更有说服力**（不是作者自造的稻草人）。

### Gaps
- mcpo 的 HTTP 方法、请求体格式、错误码映射、最新版本号未在 README 页确认；需本地起一下看 `/openapi.json`。
- 未发现有论文已经用 mcpo + RESTler/ZAP 对 MCP 做过实验（这对我们是空白也是机会）。

## Q5. 新攻击面（第一个针对某新协议/平台的扫描器）的论文如何处理"没有直接基线"？

### Takeaway
三种常见做法，且通常组合使用：(1) **改造通用工具当基线**，并统一 payload/oracle 以示公平（NAUTILUS、VOAPI2）；(2) **固定一个模块、只比另一个模块**（YuraScanner 复用 Black Widow 的 XSS 引擎、只比爬取策略；VOAPI2 的 RestTestGen+V）；(3) **对比领域内少量现有工具（哪怕定位不同）+ 大量消融**（VIPER-MCP 对比 MCPSafetyScanner 与 Cisco MCP Scanner，并做 3 个消融）。此外 VOAPI2 用"500 中真漏洞比例 2.5–5.4%"这种量化论证说明通用工具 oracle 不适配。

### Cited Findings
- **NAUTILUS**：承认"这些工具设计目的不同"，挑"能扩展自定义 payload"的工具，统一用 FuzzDB 字典，只改基线的取值不改其序列策略 — [NAUTILUS PDF §5.1](https://usenix.org/system/files/usenixsecurity23-deng-gelei.pdf)
- **VOAPI2**：同样声明"designed for different purposes"，把基线分两类分别回答不同问题（扫描器比漏洞数，REST fuzzer 比 500 与测试效率），默认配置、5 小时上限，人工核对 500 的漏洞占比；另做漏洞导向策略的消融（RQ3）并把策略移植到基线（RestTestGen+V）— [VOAPI2 PDF §5](https://usenix.org/system/files/usenixsecurity24-du.pdf)
- **YuraScanner（NDSS 2025）**：因为 Black Widow 已被证明优于 Arachni/ZAP/w3af 等，只与 Black Widow 及 BFS/Random BFS 比；检测引擎直接复用 Black Widow 的，以隔离 LLM 探索的贡献 — [YuraScanner PDF](https://www.ndss-symposium.org/wp-content/uploads/2025-388-paper.pdf)
- **Witcher（S&P 2023）**：与 Burp 比时额外做了 "BurpPlus Witcher"（把 Witcher 爬到的请求喂给 Burp）以区分"爬取"与"检测"贡献 — [Witcher](https://adamdoupe.com/publications/witcher-oakland2023.md)
- **VIPER-MCP（arXiv 2605.21392 v2，白盒，venue 未标注）【已核实】**：基线为 MCPSafetyScanner（首个多智能体动态 MCP 扫描器，三智能体 Hacker/Auditor/Supervisor；作者**改其自由文本报告 prompt 为二元判定**以便定量比较）和 Cisco AI Defense/MCP Scanner（启用 GPT-5.4 的 LLM-as-a-Judge，"最强基线配置"）；所有 LLM 组件统一用 GPT-5.4；在 130 个漏洞 + 130 个良性 MCP 服务器上：MCPSafetyScanner FPR 43.1%/FNR 63.8%，Cisco FPR 24.6%/FNR 73.1%，VIPER-MCP 0%/7.7%；消融：去 Anchor Queries FNR 34.6%、去 Prompt Evolution 40.8%、去 Mutator Scheduling 33.8% — [VIPER-MCP arXiv 2605.21392](https://arxiv.org/pdf/2605.21392)
- VIPER-MCP **没有**用任何通用 web/REST 扫描器做基线（正文基线只有两个 MCP 专用工具）— [VIPER-MCP arXiv 2605.21392](https://arxiv.org/pdf/2605.21392)
- MCPSafetyScanner 的出处：Radosevich & Halloran, "MCP safety audit: LLMs with the Model Context Protocol..."（VIPER-MCP 参考文献 [15]）— [VIPER-MCP arXiv 2605.21392](https://arxiv.org/pdf/2605.21392)

### Inferences
- 建议我们的基线矩阵（按论证强度排序）：
  1. **MCP 专用动态工具**：MCPSafetyScanner（同 VIPER-MCP 的改法：二元化输出、统一 LLM 后端）、mcp-fuzzer/mcpsec 等开源 MCP fuzzer（payload 型、无 oracle 确认）。Cisco MCP Scanner 是静态/描述级审计，可作为"只看描述的 LLM-as-judge"基线——这与我们"只用描述分类参数"直接相关，可以证明"仅靠描述判断"误报高、必须执行确认。
  2. **通用工具 + mcpo 转接**：ZAP Active Scan（OpenAPI 导入 + OAST）、RESTler / EvoMaster 黑盒 / Schemathesis（预期主要报 0 或少量 500，可像 VOAPI2 那样统计"500 中真漏洞占比"）。
  3. **注入专用工具组合**：commix + SSRFmap + dotdotpwn/ZAP 路径穿越 + SSTImap，逐参数打。
  4. **LLM-only 基线**：同一 LLM 直接读 tools/list 并自由调用（类似 MCPSafetyScanner 的 agent 范式，但无我们的 oracle），量化 oracle 的价值。
  5. **消融**：去语义参数分类（对所有参数打所有 payload）、去序列构建智能体（只单调用）、逐个去 oracle（OOB/时延/回读/差分对照），以及把我们的序列+取值喂给基线（"Baseline+Ours-seq"），学 RestTestGen+V / BurpPlus。
- 由于我们的论文口径是"服务器级二元 + 只报人工验证为真"，所有基线应同样折算为服务器级二元（VIPER-MCP 即以服务器为单位报 TP/FN/TN/FP），并在 44 正/24 负数据集上跑，便于直接比较。
- VIPER-MCP 未与通用扫描器对比，这给我们留下"首个系统性展示通用 web/REST 工具在 MCP 上失效"的空间，可作为一个小的 motivating measurement。

### Gaps
- 未调研 web/REST 之外的"新协议首个扫描器"例子（如智能合约、IoT 协议、GraphQL、gRPC、浏览器扩展）的基线处理；GraphQL 安全 fuzzing 文献可能是更接近的类比（同为 schema 驱动、非 REST），本次未覆盖。
- 未读 MCPSafetyScanner 原文核实其开源状态与 venue。
- 未核实 VIPER-MCP 是否已被会议接收。
