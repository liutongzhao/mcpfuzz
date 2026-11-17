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
├── deploy/           实验基础设施（批量检测单元、OOB 采集器、冻结批次）
├── dataset/          漏洞数据集流水线脚本（采集/标注/分析 CVE）
├── data/             数据集产物（GB 级，不进 git）
├── docs/             中文设计文档和论文资料
├── research_notes/   调研笔记（相关工作、baseline 工具）
├── runs/             本地扫描结果（calchas 默认输出，不进 git）
└── .venv/            本地虚拟环境（不进 git）
```

| 目录 | 放什么 | 不放什么 | 进 git |
|---|---|---|---|
| `calchas/` | 检测工具源码。子模块：`cli/` 命令行、`sink/` 阶段一参数分类、`orchestrator/` 阶段二序列构建与攻击编排、`payload/` 载荷电池、`oracle/` 阶段三执行确认；`__about__.py` 存名字/版本 | 实验脚本、数据、针对个别服务的特判 | 是（`payload/_raw/` 词表除外） |
| `dev/` | 开发者自用的调试/自检脚本：`dump_catalog.py`、`dump_sinks.py`、`selftest_oracle.py`（要连靶机）。在仓库根用 `.venv/bin/python dev/xxx.py` 运行 | 用户会用到的功能（这类功能做成 `calchas` 子命令） | 是 |
| `deploy/cells/` | 大规模批量检测的 docker-compose 单元（gateway+oob+runner）、镜像构建与批次装配脚本 | 镜像包 `*.tar.gz`、真实批次清单、运行结果、运行台账 | 是（产物除外，见 `deploy/cells/.gitignore`） |
| `deploy/infra/oob/` | OOB 带外回连采集器 | — | 是 |
| `deploy/batches/` | 已冻结批次的记录，一批一个子目录，冻结后只读 | 进行中的批次 | 是 |
| `dataset/` | CVE/GHSA/OSV 漏洞数据集流水线：`download.py`→`collect.py`→`classify.py`→`analyze.py`，产物写到 `data/` | 数据本身 | 是（`llm_config.py` 含 key，除外） |
| `data/` | 数据集流水线产物（`raw/`、`candidates.*`、`labels*`、`analysis/`）、ground truth（`groundtruth/`：数据集总表、检测结果、正负样本清单、定型检测日志）、服务器归档（`server_archive/`：从检测服务器撤下的实验数据冷备，一台一次一个 tar.gz） | 代码 | 否 |
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
```

## 待办

- 检测服务器（43.133.80.249 等）的目录结构也要按同样思路规范化，届时把服务器目录约定补到本文件，并更新 `deploy/infra/oob/mcpfuzz-oob.service` 里的旧路径。

## Git 规范

- **所有 commit 信息必须使用中文书写**（标题和正文均使用中文）。
