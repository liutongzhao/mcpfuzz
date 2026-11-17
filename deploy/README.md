# deploy —— 实验基础设施

这里放**跑实验**用的部署件。工具本体在仓库根的 `calchas/`，这里不放扫描器源码。

| 子目录 | 作用 | 状态 |
|---|---|---|
| `cells/` | 大规模批量检测单元（docker-compose：gateway + oob + runner），把全网 MCP 切批并行扫 | 在用，详见 `cells/README.md` |
| `infra/oob/` | 带外回连（OOB）采集器，纯标准库。`collector.py` 也是 README 里推荐给用户自建 OOB 的参考实现 | 在用 |
| `batches/` | 已冻结批次的权威记录（清单、网关配置、扫描汇总）。一批一个子目录，冻结后只读 | 只读归档 |

## 约定

- 新增一类部署件，先在本表和仓库根 `CLAUDE.md` 的目录表里登记，再建目录。
- 镜像包（`*.tar.gz`）、运行结果、真实批次清单都不进 git，见 `cells/.gitignore`。
- `infra/oob/mcpfuzz-oob.service` 写的是旧服务器路径（`/home/ubuntu/mcpfuzz/...`），检测服务器规范化时一起更新。
