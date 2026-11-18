# CLAUDE.md

本文件为 Claude Code 在本仓库中工作时提供指引。

## 项目简介

**Calchas**：MCP（Model Context Protocol）服务器的黑盒注入漏洞检测工具，附带配套的实验基础设施和研究资料。
- 工具以 PyPI 包 `mcp-calchas` 发布，命令和 import 名都是 `calchas`。
- GitHub 仓库：https://github.com/liutongzhao/mcpfuzz
- 开发分支是 `calchas`，不合回 main。

## 目录结构（权威登记表）

```
/
├── calchas/          工具本体（Python 包，唯一会打进 PyPI 包的代码）
├── pyproject.toml    打包配置（版本号在 calchas/__about__.py）
├── README.md         工具对外说明（英文，即 PyPI 页面）
├── LICENSE           Apache-2.0
├── dev/              开发调试脚本（不进包）
├── deploy/           实验基础设施（实验服务、批量检测单元、OOB 采集器、冻结批次）
├── dataset/          漏洞数据集流水线脚本（采集/标注/分析 CVE）
├── mcp-cve-dataset/  对外贡献的 MCP CVE 复现数据集（一 CVE 一目录，docker+poc 自包含）
├── data/             数据集产物（GB 级，不进 git）
├── docs/             中文设计文档和论文资料
├── research_notes/   调研笔记（相关工作、baseline 工具）
├── runs/             本地扫描结果（calchas 默认输出，不进 git）
└── .venv/            本地虚拟环境（不进 git）
```

| 目录 | 放什么 | 不放什么 | 进 git |
|---|---|---|---|
| `calchas/` | 检测工具源码。子模块：`cli/` 命令行、`sink/` 阶段一参数分类、`orchestrator/` 阶段二序列构建与攻击编排、`payload/` 载荷电池、`oracle/` 阶段三执行确认；`__about__.py` 存名字/版本 | 实验脚本、数据、针对个别服务的特判 | 是（`payload/_raw/` 词表除外） |
| `dev/` | 开发者自用的脚本：调试/自检 `dump_catalog.py`、`dump_sinks.py`、`selftest_oracle.py`（要连靶机），在仓库根用 `.venv/bin/python dev/xxx.py` 运行；发版 `release.sh`（改版本号→打包→检查→试装→上传→打标签） | 用户会用到的功能（这类功能做成 `calchas` 子命令） | 是 |
| `deploy/services/` | 服务器 A 上长期运行的实验服务的 compose 配置：`oob/`（calchas-oob）、`gateway/`（calchas-gateway + `configure.sh` + 扩展镜像 `Dockerfile.ext`：补齐 Chromium/docker CLI/Jij/vegalite/knowns 等被测服务依赖），两者通过 docker 网络 `calchas-net` 互通。同步到 A 的 `~/experiment/services/` 运行 | 运行数据 `data/`、密码 `.env`、构建缓存种子 `.uv-seed/`、包缓存 `cache/` | 是（`data/`、`.env`、`.uv-seed/`、`cache/` 除外） |
| `deploy/cells/` | 大规模批量检测的 docker-compose 单元（gateway+oob+runner）、镜像构建与批次装配脚本 | 镜像包 `*.tar.gz`、真实批次清单、运行结果、运行台账 | 是（产物除外，见 `deploy/cells/.gitignore`） |
| `deploy/infra/oob/` | OOB 带外回连采集器 | — | 是 |
| `deploy/batches/` | 已冻结批次的记录，一批一个子目录，冻结后只读 | 进行中的批次 | 是 |
| `dataset/` | CVE/GHSA/OSV 漏洞数据集流水线：`download.py`→`collect.py`→`classify.py`→`analyze.py`，产物写到 `data/` | 数据本身 | 是（`llm_config.py` 含 key，除外） |
| `mcp-cve-dataset/` | 对外贡献的 MCP CVE 复现数据集。每个 CVE 一个自包含子目录 `<CVE或GHSA>__<后端key>/`：`Dockerfile`（通用：node+uv+git+supergateway，把 stdio 服务用 supergateway 包成 HTTP `/mcp`）+ `vulnerable/`（漏洞版 compose，必有）+ `patched/`（修复版 compose，有修复版才建）+ `poc.py`（连 MCP 端点触发漏洞，按漏洞类有不同载荷/判据）+ `verify.sh`（差分验证）+ `README.md` + `meta.json`；SSRF 类多一个 `_collector/`（内网金丝雀回连目标）。对外统一走 HTTP 端点（方案 A）。`_build/` 是生成器：`build_facts.py`（从 round2 总表+gt_backends+cve_reference join 出 `facts.json`）→ `generate.py`（模板批量生成所有条目），改模板后重跑即可全量再生。样本身份对齐 `data/groundtruth/round2/`，但本目录是可独立开源的干净产物，不依赖 round2 网关/OOB。已同步到服务器 B `/home/star/cuz/mcp-cve-dataset/` | 检测器源码、实验配置、针对个别服务的特判 | 是 |
| `data/` | 数据集流水线产物（`raw/`、`candidates.*`、`labels*`、`analysis/`）、ground truth（`groundtruth/`：按轮次分 `round1_frozen/` 旧轮只读 + `round2/` 当前轮；样本定义只认 `round2/数据集总表.md`）、服务器归档（`server_archive/`：从检测服务器撤下的实验数据冷备，一台一次一个 tar.gz） | 代码 | 否 |
| `docs/` | 中文设计文档（各模块设计、判定方法论、漏洞类型）、论文资料（框架、方法讨论、实验计划、引言草稿）、`参考论文/` PDF | 代码、数据 | 是（`参考论文/` 除外） |
| `research_notes/` | 相关工作和 baseline 工具调研 | 自己的设计文档（放 `docs/`） | 是 |
| `runs/` | `calchas scan` 在仓库根运行时的默认输出 | — | 否 |

## 归置规范

1. **对号入座**：新文件按上表放进对应目录。不确定放哪时先问，不要在根目录或随手新建目录堆东西。
2. **新增必须登记**：新建顶层目录、在已有目录下新增一类内容（新子目录、新类型脚本），或改变某个目录的用途时，**先更新上面的目录树和登记表**，再落文件。登记表要和实际目录一致。
3. **没用就删**：被新实现取代的脚本、旧产物目录、构建残留（`dist/`、`*.egg-info`、`__pycache__`、`.DS_Store`）及时删除，不留"以后可能有用"的死代码。git 里有历史，删了也能找回。
4. **产物不进 git**：扫描结果、镜像包、数据集、密钥一律走 `.gitignore`。新增一种产物时同步更新 `.gitignore`；如果会影响 runner 镜像构建上下文，还要同步 `.dockerignore`。
5. **工具和实验分开**：`calchas/` 必须对任意 MCP 通用，不写死服务器地址、密钥或个别服务的特例。实验用的配置、清单、脚本放 `deploy/` 或 `dev/`。

## 常用命令

```bash
python3 -m venv .venv && .venv/bin/pip install -e .   # 开发安装（仓库根）
.venv/bin/calchas selftest                             # 离线自检
.venv/bin/python -m build                              # 打包到 dist/
dev/release.sh 0.1.0                                   # 发版演练（打包+检查+试装，不上传）
dev/release.sh 0.1.0 --upload                          # 正式发版到 PyPI（加 --testpypi 则发到测试站）
```

## 待办

- `deploy/infra/oob/mcpfuzz-oob.service` 写的是 43.133 的旧路径，43.133 已不再做实验，改 `deploy/cells` 时一并处理。

## 实验服务器

- 实验统一在**服务器 A** 的 `/home/cuzisme/experiment` 下进行（SSH：`192.168.0.106`，经 43.133.80.249:60022 的 frp 转发）。目录登记表和操作手册在服务器上的 `experiment/README.md`，在那里新增内容同样要先登记。
- 检测器只用**发布的 pip 包** `mcp-calchas`，不在服务器上放源码。
- 43.133.80.249 不再做实验，只作为 A 的 SSH 跳板。

## Git 规范

- **所有 commit 信息必须使用中文书写**（标题和正文均使用中文）。
