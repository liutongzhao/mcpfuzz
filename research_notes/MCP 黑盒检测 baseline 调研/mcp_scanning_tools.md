# MCP Security Scanning Tools (status as of Nov 2026), and which could serve as a black-box server-side injection baseline

Scope note: these notes come from about 20 web searches and fetches done on 2026-11-11. Star counts and feature claims are as shown on the fetched pages. I did not run any tool. Where I only have the README's own claims, I say so.

## Q1. What do the well-known MCP security tools actually check? (LLM-side / description-level vs. server-side)

### Takeaway
Most widely adopted or branded MCP "scanners" work on the LLM side or on descriptions and config. They look at tool descriptions for poisoning or prompt injection, rug-pulls, toxic flows, secrets and auth. Some add static or LLM review of source code. None of the big-name tools (Snyk Agent Scan / ex-Invariant mcp-scan, Cisco mcp-scanner, Ramparts, Enkrypt) sends server-side injection payloads to tool parameters and confirms that they executed.

### Cited Findings
**Snyk Agent Scan (formerly Invariant Labs mcp-scan)**
- Snyk acquired Invariant Labs in June 2025 and rebranded MCP-Scan as "Snyk Agent Scan". v0.4.13 is listed as the April 2026 release — [appsecsanta](https://appsecsanta.com/mcp-scan); [eSEOspace](https://eseospace.com/blog/invariant-labs-mcp/)
- The old `mcp-scan` PyPI package now redirects to `snyk-agent-scan` — [Rubin Lake radar](https://rubinlake.com/en/technology-radar/ai-security-and-governance/agent-scan)
- It detects prompt injection, tool poisoning, tool shadowing and toxic flows (data paths that cross trust boundaries), and it also covers agent skills. It runs as `uvx snyk-agent-scan@latest` — [Tenki](https://tenki.cloud/blog/mcp-security-scanning-ai-agents)
- Toxic Flow Analysis models an agent's tool flows as a graph and scores sequences that could lead to violations — [Invariant Labs blog](https://invariantlabs.ai/blog/toxic-flow-analysis). Snyk pairs LLM judges with deterministic rules — [Snyk blog](https://snyk.io/blog/snyk-vercel-securing-agent-skill-ecosystem)
- Scans send tool names and descriptions to Snyk's API and need a Snyk token — [eSEOspace](https://eseospace.com/blog/invariant-labs-mcp/)
- A 2026 comparison describes mcp-scan as "config-level issue detection" — [devtoollab / appsecsanta audit (via search snippet)](https://appsecsanta.com/research/mcp-server-security-audit-2026)

**Cisco AI Defense mcp-scanner** (OSS, PyPI `cisco-ai-mcp-scanner`)
- It has three engines: YARA rules, LLM-based analysis (any LiteLLM model) and the Cisco AI Defense inspect API. They can run together or separately. It targets malicious tools, prompts and resources — [GitHub](https://github.com/cisco-ai-defense/mcp-scanner); [PyPI 4.8.0](https://pypi.org/project/cisco-ai-mcp-scanner/4.8.0/)
- Its "Behavioural Code Scanning" / supplychain mode scans an MCP server's source code with an LLM, looking for things like functions whose behavior does not match their description and hidden network calls. It needs source code — [PyPI 4.2.0](https://pypi.org/project/cisco-ai-mcp-scanner/4.2.0/)
- One independent test ran Cisco plus another OSS scanner on 33 servers. YARA flagged 27 patterns across 433 tools in 10 servers, and "only 6 represent genuine security concerns" — [appsecsanta research](https://appsecsanta.com/research/mcp-server-security-audit-2026)

**Ramparts (Highflame, formerly Javelin)**
- An OSS Rust scanner (Apache-2.0 per one roundup). It scans MCP servers, including remote URLs with auth headers. It is "a comprehensive security scanner for MCP servers with YARA rules and static analysis capabilities", has a REST server mode for CI, newer versions also scan agent skills, and findings map to the OWASP MCP Top 10 — [docs.rs](https://docs.rs/crate/ramparts/0.8.1); [Docker Hub](https://hub.docker.com/r/mcp/ramparts); [eSEOspace roundup](https://eseospace.com/blog/best-mcp-security-tools/)
- CVE-2026-120202: versions 0.8.1–0.8.10 skip nested directories and .pyc files when scanning skill bundles, which allows a scan bypass — [VulnCheck](https://www.vulncheck.com/advisories/highflame-ramparts-0.8.1-through-0.8.10-skill-bundle-scan-bypass-via-nested-pyc)

**Nova Proximity**
- Listed as OSS (GPL-3.0) with custom detection rules on a rule engine (it enumerates the server and matches its tools/prompts against Nova rules) — [eSEOspace roundup](https://eseospace.com/blog/best-mcp-security-tools/)

**MCPSafetyScanner (Leidos; Radosevich & Halloran, arXiv 2504.03767)**
- A multi-agent auditor. It takes an MCP config, generates adversarial samples from the server's tools, prompts and resources, searches for related vulnerabilities and remediations, and writes a report. Code: github.com/johnhalloran321/mcpSafetyScanner — [arXiv 2504.03767](https://arxiv.org/html/2504.03767v2); [emergentmind summary](https://www.emergentmind.com/topics/mcpsafetyscanner)

**Enkrypt AI MCP Scan (commercial)**
- It accepts "GitHub repos, npm packages, or remote endpoints" and covers "configuration, permissions, tool schemas, endpoints, and common vulnerability patterns". The risk categories it lists are prompt injection / tool-steering, sensitive data / PII, response integrity and policy / over-privilege. Command injection, path traversal and SSRF are not named. Pricing is not public — [enkryptai.com/mcp-scan](https://enkryptai.com/mcp-scan)
- Enkrypt published "We scanned 1,000 MCP servers: 33% had critical vulnerabilities" — [Enkrypt blog](https://enkryptai.com/blog/we-scanned-1-000-mcp-servers-33-had-critical-vulnerabilities). A single source reports that Anaconda acquired Enkrypt on 2026-08-04 (UNVERIFIED, one source only) — [pasqualepillitteri.it](https://pasqualepillitteri.it/en/news/9893/anaconda-enkrypt-ai-mcp-server-flaws)

**Other commercial vendors** (marketing-level claims only)
- Pillar Security offers MCP discovery, red-teaming assessments and runtime protection — [search summary of Akto/TrueFoundry listicles](https://www.akto.io/blog/mcp-security-tools)
- Lasso has an open-source MCP Gateway (MIT), plus a commercial platform for discovery, risk scoring and tool-call monitoring — [eSEOspace Lasso](https://eseospace.com/blog/lasso-security-mcp/)
- Protect AI is described by one review as a generic AI-security platform that misses MCP-specific code-level vulnerabilities — [spiderrating review](https://spiderratingv2.pages.dev/blog/7-open-source-ai-tool-security-scanners-reviewed-in-2026)
- SandboxAQ (AQtive Guard) offers an "AI-powered code analysis" MCP scanner that needs source — [AQtive Guard](https://www.aqtiveguard.com/blogs/mcp-server-security-scanner)
- NeuralTrust has an MCP scanner product page — [neuraltrust.ai](https://neuraltrust.ai/mcp-scanner)
- CSA RiskRubric MCP Scanner has a spec/architecture note (a risk-rating spec, March 2026) — [CSA labs](https://labs.cloudsecurityalliance.org/agentic/csa-research-note-riskrubric-mcp-scanner-spec-20260327/)

**Academic: MCPGuard (PKU + Tencent, arXiv 2510.23673)**
- The paper body is mostly a survey of MCP threats: agent hijacking, classic web flaws such as CMDi/PT/SSRF/SQLi, and supply chain. It "introduces the AIG tool", which is likely Tencent AI-Infra-Guard, a red-teaming platform that includes MCP server risk scanning. The HTML version reports no evaluation numbers and links no MCPGuard repo — [arXiv 2510.23673](https://arxiv.org/html/2510.23673v1)

### Inferences
- The main ecosystem tools (Snyk, Cisco, Ramparts, Proximity, Enkrypt) are effectively LLM-side or "is this server malicious?" scanners. Their threat model is a *malicious* server attacking the agent. Ours is a *vulnerable* server being attacked by a black-box client. They are not a fair head-to-head baseline for injection detection. At most, the source-code modes of Cisco, AQtive Guard and mcpsec audit could be compared as a white-box or LLM-static reference point.
- Cisco's behavioral mode and MCPSafetyScanner use LLM reasoning over code or features without confirming by execution. That makes them useful as "LLM-judged, no confirmation" contrast points that probably have high false-positive rates, which the appsecsanta 6/27 figure supports.

### Gaps
- **Trail of Bits mcp-context-protector:** search returned nothing. From prior knowledge (unverified this session), it is a wrapper/proxy that pins tool descriptions with trust-on-first-use and sanitizes ANSI and other output. That is defensive and client-side, with no payload testing.
- **MCP-Shield:** no primary page was found. From prior knowledge (unverified), it is a Node CLI that scans locally installed MCP configs for tool poisoning, exfiltration and shadowing in descriptions, with optional Claude analysis. It is description-level only.
- **Golf, mcp-watch:** not covered by any search result.
- **Semgrep MCP rules:** not covered. mcpsec says it ships 149 Semgrep rules of its own (see Q2).
- **OWASP MCP Top 10 project page:** not fetched.
- I have no GitHub star counts for Snyk Agent Scan, Cisco mcp-scanner or Ramparts.

## Q2. Is there any tool that dynamically attacks MCP tool parameters for server-side injection and confirms exploitation?

### Takeaway
Yes. As of mid/late 2026, a cluster of tools sends live injection payloads to MCP tool parameters. The closest to our design are **mcpsnare** (MIT; CMDi, code injection, SSRF and PT with canary, timing and OOB oracles; stdio plus streamable HTTP), **PortSwigger's official "MCP Server Scanner" BApp** (tool-argument fuzzing for PT plus OOB RCE via Burp Collaborator), **mcpsec** (MIT, 26 stars, runtime CMDi/PT/SSRF/eval probes with optional LLM payloads), and **MCPwn** (AGPL, marker/timing/canary confirmation). All are small and recent and none publishes a benchmark with precision and recall. None lists **argument injection** as a class, and none describes LLM-driven semantic parameter classification or multi-call sequence construction. These tools are a real novelty threat to "first black-box dynamic detector", and they are also the natural baselines.

### Cited Findings
**mcpsnare** (Dennis Sepede / DenSec, PyPI, v0.5.0 released 2026-07-23, MIT)
- It enumerates tools and sends payloads to live tool params, including nested objects, array items, enum-gated params, free-form containers and resource-template URI params. A passive lens checks the manifest without calling tools — [PyPI mcpsnare](https://pypi.org/project/mcpsnare/)
- Classes: command injection (CWE-78), code/eval injection (CWE-94), SSRF (CWE-918), path traversal (CWE-22), plus missing auth, info leak and SQLi. Argument injection is not listed — [PyPI](https://pypi.org/project/mcpsnare/)
- Oracles: canary reflection, calibrated timing (time-based probes only in aggressive mode), baseline diffs, and OOB callbacks for blind CMDi and SSRF (`local` default / `interactsh` / `none`). Confidence levels are CONFIRMED / FIRM / TENTATIVE — [PyPI](https://pypi.org/project/mcpsnare/)
- Transports: stdio and streamable HTTP, with custom headers and auth — [PyPI](https://pypi.org/project/mcpsnare/)

**PortSwigger "MCP Server Scanner" BApp** (author Peter Hendy, PortSwigger; v0.1.0; last updated 2026-06-30)
- It discovers tools, resources, resource templates and prompts, and builds JSON-RPC 2.0 requests with fuzzable insertion points for Burp's active and passive scanner. It performs "tool-argument fuzzing for path traversal and out-of-band RCE detection" via Burp Collaborator, plus auth-bypass, DNS-rebinding and secrets-in-metadata checks. Users can choose which tools are included in active scans — [PortSwigger BApp Store](https://portswigger.net/bappstore/331a84edb4134705ad2ef25b90f626f2)

**mcpsec** (manthanghasadiya, MIT, 26 stars, 142 commits)
- Static audit (needs source): 3,450+ regex sink patterns, 149 Semgrep rules, Python/JS AST taint, and LLM or heuristic reachability — [GitHub mcpsec](https://github.com/manthanghasadiya/mcpsec)
- Runtime mode: connects to a live server over stdio or HTTP and runs payload sets: 138 CMDi, 104 PT, 81 SSRF (including resource-URI), plus eval/exec sinks, SQLi, SSTI, deserialization, XXE and others. The optional `--ai` flag adds LLM-generated payloads. The README does not explain the confirmation oracle beyond "PoC evidence" — [GitHub](https://github.com/manthanghasadiya/mcpsec)
- It claims 6 CVEs, but only CVE-2026-35394 (mobile-mcp URL scheme injection) is named. It also reports a radare2-mcp shell-escape RCE and several SDK DoS crashes. No benchmark or FP metrics — [GitHub](https://github.com/manthanghasadiya/mcpsec)

**MCPwn** (kodivante, Go, AGPL-3.0, 1 star, 11 commits)
- Static schema linting, an optional Python/JS/TS taint analyzer, and dynamic probes with benign payloads: echo with a unique marker, short sleeps, temp-file read-back, `$(echo MARK)`/backticks, and a 127.0.0.1 canary for SSRF. A hardcoded deny-list blocks dangerous commands. Confirmed findings get confidence 95 and static ones 70. Transports: stdio, SSE and Streamable HTTP. The README is inconsistent about rule counts — [GitHub MCPwn](https://github.com/kodivante/MCPwn)

**mcpfuzz** (NAMAN-VERMA-02, Go, Apache-2.0, 0 stars, v0.1)
- Its `--active` mode calls allowlisted tools with PT payloads aimed at a random canary file outside the allowed root, and with shell payloads (`;`, `|`, `&&`, `$()`, backticks, newline) that `touch` a marker file. A finding requires the canary to appear in the output or the marker file to exist. It is stdio only, has been tested only on its own vulnerable/fixed test servers, and must run in an isolated Docker container — [GitHub mcpfuzz](https://github.com/NAMAN-VERMA-02/mcpfuzz)
- Inference: the marker-file oracle needs the scanner to share a filesystem with the server, so it is not purely black-box.

**mcp-guard** (ShovalBenjer / Zion-sewers, Python, MIT, 1 star, 93 commits)
- Schema-aware payloads to every param (29 string, 37 URI, 9 number). It probes for shell injection, SSRF, overflow, type confusion and prompt injection. It states: "Findings are response-pattern classifications for investigation, not confirmed exploits." Stdio only — [GitHub mcp-guard](https://github.com/ShovalBenjer/mcp-guard)

**mcp-gauntlet / mcp-fuzz** (studiomeyer-io, Rust, MIT, 0 stars)
- It sends injection strings (PT, SQLi, command, template, CRLF and others) "purely as data, never executed". Findings are only crash, hang, -32603 internal error, or accepted-invalid-input. In effect this is robustness fuzzing, not exploitation confirmation. Transports: stdio and HTTP, with SARIF output — [GitHub mcp-gauntlet](https://github.com/studiomeyer-io/mcp-gauntlet)

**fuzzd** (ksek87, Rust) — an argument-boundary fuzzer covering PT, command injection and others. Its GitHub Action was "in progress". I did not fetch the README — [GitHub fuzzd](https://github.com/ksek87/fuzzd)

**Burp ecosystem, other**
- MCPwned: a Burp extension for testing MCP servers that inspects client–server HTTP traffic for protocol flaws and does "semi-automated fuzzing of MCP interfaces". The post is dated 2026-04-28, and its vendor tag says Fenrisk — [PT dbugs](https://dbugs.ptsecurity.com/news/mcpwned-a-burp-suite-extension-for-testing-model-context-protocol-servers-20260428)
- TrustedSec MCP-ASD: a Burp extension for passive and active *discovery* of MCP servers, then targeted manual exploitation — [TrustedSec blog](https://trustedsec.com/blog/mcp-in-burp-suite-from-enumeration-to-targeted-exploitation)
- six2dez burp-ai-agent: adds MCP tooling and AI-assisted analysis to Burp. It drives Burp, it does not scan MCP — [ecosyste.ms](https://awesome.ecosyste.ms/projects/github.com%2Fsix2dez%2Fburp-ai-agent)

**Nuclei / ZAP / Metasploit**
- The Nuclei search results were all MCP servers that *wrap* Nuclei so an LLM can run scans (mark3labs/nuclei-mcp, ProjectDiscovery MCP, etc.). None were Nuclei templates that attack MCP servers — [mark3labs nuclei-mcp](https://playbooks.com/mcp/mark3labs-nuclei); [glama ProjectDiscovery](https://glama.ai/mcp/servers/intelligent-ears/pd-tools-mcp/tools/nuclei)

**Related white-box work (for context)**
- VIPER-MCP (CodeQL + LLM fuzzing, white-box) claims 106 0-days and 67 CVEs across CMDi, SSRF and PT. This came from a search snippet, not verified this session; see the existing project memory note on VIPER-MCP — (search result summary, no primary URL fetched)

### Inferences
- **Best baseline candidates for our 44+/24- dataset** (all speak HTTP; our servers sit behind an mcphub gateway on a public IP):
  1. **mcpsnare**: same four classes (CMDi, code injection, SSRF, PT), streamable HTTP, OOB oracle. This is the closest analogue and the most important to compare against. Its argument-injection coverage is presumably weak or missing.
  2. **PortSwigger MCP Server Scanner BApp**: an industry-standard baseline ("Burp active scan"). It covers only PT and OOB RCE, and running it is GUI-driven or semi-automated, so it is harder to script at scale.
  3. **mcpsec runtime mode**: covers CMDi, PT, SSRF and eval over HTTP. Run it with and without `--ai`.
  4. **MCPwn dynamic mode**: has HTTP transport and marker/timing oracles.
  - Stdio-only tools (mcpfuzz, mcp-guard) would need each server launched locally as a subprocess. That does not match our gateway/HTTP setup, so they are weaker baselines. mcp-gauntlet only detects crashes and is unsuitable.
- The likely key differentiators to argue for us: (a) argument injection as a class; (b) LLM semantic parameter classification and sink inference, versus spraying payloads into every string or URI param; (c) multi-step sequence construction (state setup before the vulnerable call); (d) a large-scale measurement; and (e) measured precision and recall on a CVE-backed ground truth, which none of these tools publish.
- All of these tools are tiny (0–26 stars) and recent (2026). Reviewers may still treat them as prior art, so the paper should cite them and ideally run at least mcpsnare and the Burp BApp as baselines.

### Gaps
- I do not have last-commit dates for mcpsec, MCPwn, mcpfuzz or mcp-guard. Release dates are unknown except for mcpsnare (2026-07-23) and the Burp BApp (updated 2026-06-30).
- mcpsec's actual confirmation oracle is not documented in its README.
- MCPwned's repo and exact capabilities were not verified.
- No ZAP add-on or Metasploit module for attacking MCP servers was found. These were not specifically searched (only Nuclei was), so treat this as not-found rather than confirmed absent.
- There are other active tools I did not check: `adriyansyah-mf/mcp-pentest` (its own issue #2 reports CMDi/SSRF/PT *in* the tool), Tencent AI-Infra-Guard's MCP module, and `mcp-security-scanner` (badchars).

## Q3. Vulnerable-by-design MCP servers / benchmarks

### Takeaway
Several vulnerable-by-design MCP labs exist. Most focus on LLM-side issues (prompt injection, tool poisoning), while a few include server-side PT and CMDi. MCPSecBench is the only formal benchmark found, and it targets attacks on MCP hosts and clients, not server-side injection detection. They could serve as a sanity check or extra demo targets, but they are not substitutes for our CVE-backed dataset.

### Cited Findings
- DVMCP (harishsg993010): an educational Python lab with 10 challenges at 3 difficulty levels. It is mainly about prompt injection and tool poisoning — [glama DVMCP README](https://glama.ai/mcp/servers/@harishsg993010/damn-vulnerable-MCP-server/blob/79734c19f5104cd11486c90926d245560f53befa/README.md); [playbooks](https://playbooks.com/mcp/harishsg993010/damn-vulnerable-mcp-server)
- appsecco vulnerable-mcp-servers-lab: a collection with one standalone server per vulnerability, for training and pentesting — [sourcepulse](https://www.sourcepulse.org/projects/28027859); [skills.sh](https://www.skills.sh/aradotso/mcp-skills/vulnerable-mcp-servers-lab)
- IntegSec VulnerableMCP: "20+ exploits across path traversal, injection, tool poisoning, and more" — [GitHub](https://github.com/integsec/VulnerableMCP)
- rockysec vulnerable-notes-mcp: a lab for the PT and CMDi flaws described in "Auditing an MCP server: 2 flaws that keep showing up" — [Rockysec](https://rockysec.com/en/auditing-an-mcp-server/)
- MCPGoat (sabyasachidhal) — [mcpservers.org](https://mcpservers.org/servers/sabyasachidhal/mcpgoat)
- bad-mcp (canack): intentionally *malicious* servers, where the server is the attacker, so the opposite threat model — [lobehub](https://lobehub.com/zh/mcp/canack-bad-mcp)
- MCPSecBench (arXiv 2508.13220): 17 attack types evaluated against Claude Desktop, OpenAI and Cursor hosts. It bundles prompts, servers, clients, attack scripts and protections — [arXiv](https://arxiv.org/pdf/2508.13220v3)
- mcpfuzz ships paired vulnerable and fixed test servers for its CI — [GitHub](https://github.com/NAMAN-VERMA-02/mcpfuzz)

### Inferences
- IntegSec VulnerableMCP, appsecco lab and rockysec could be run as a small "toy suite" to show that our tool and the baselines all catch textbook cases. The real comparison should then be on the 44/24 CVE dataset, where we expect our semantic and sequence features to matter.

### Gaps
- I did not check per-lab counts of server-side injection challenges (CMDi/PT/SSRF/code/argument), license or maintenance status.
