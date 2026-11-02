# 第一批 MCP 服务（batch1）

本目录**冻结**记录我们检测的第一批 MCP 服务，作为后续分析与复现的权威基准。

## 由来

- 2026-11-01 从 MCP 市场抓取 100 个服务，批量导入 mcphub 网关（腾讯云 43.133.80.249:3000），用 `mcpfuzz` 批量扫描（批次名 `第一批100个mcp服务`，经网关单后端直通口 `/mcp/{server}`，enable→扫→disable）。
- 100 个里 **49 个检测成功**（服务起来、工具列出、完整扫完），**51 个失败**（50 个后端 `tools=0` 没起来、1 个 `NoneType` 报错）。
- **第一批 = 这 49 个检测成功的服务。** 其余 51 个已于冻结时从网关删除（见下）。
- 全部为 npm 包、`npx` 拉起、stdio 接入，版本已 pin；env 无密钥。

## 规模

| 口径 | 数量 |
|---|---:|
| 服务（成功检测） | **49** |
| 确认有（confirmed，按参数计） | 9 |
| 疑似有（suspected） | 31 |
| 疑似无（clean） | 1797 |
| 未触达（unreached） | 403 |

> 注：9 个"确认"是初步判决，**尚未逐个过"本职功能 vs 真漏洞"（dangerous-by-design）复核**——`shell-exec-mcp`、`docker-mcp-server`、`filecommander` 等很可能命中的是工具本职功能。深度分析阶段逐个核实。

## 文件

| 文件 | 内容 |
|---|---|
| `manifest.json` | 49 个服务的权威清单：网关名、npm 包、版本、启动命令、扫描结果计数、run_dir |
| `services.txt` | 49 个网关后端名（供 `--batch` 重跑） |
| `targets.txt` | 49 个目标 URL（`/mcp/{server}`，供 `--batch` 重跑） |
| `gateway_configs.json` | 49 个服务在网关里的原始配置（用于恢复/重新导入网关） |
| `batch_summary.json` / `batch_summary.md` | 本批扫描的原始汇总（含成功 49 + 失败 51 的完整记录） |

**完整扫描产物**（每个目标的 `report.md`/`findings.json`/`run.log`/`events.jsonl`）冻结在服务器：
`~/mcpfuzz/prototype/runs/第一批100个mcp服务/` 及归档 `~/mcpfuzz/prototype/runs/第一批100个mcp服务.frozen.tar.gz`。

## 49 个服务一览（按确认/疑似降序）

| # | 网关名 | npm 包 | 确认 | 疑似 | 疑似无 | 未触达 |
|---|---|---|---:|---:|---:|---:|
| 1 | `io.github.bitofacoder_omni-mcp-server` | `@bitofacoder/omni-mcp-server@1.1.1` | 2 | 3 | 9 | 0 |
| 2 | `io.github.ellmos-ai_ellmos-filecommander-mcp` | `ellmos-filecommander-mcp@1.11.4` | 2 | 1 | 80 | 10 |
| 3 | `io.github.lukisch_bach-filecommander-mcp` | `bach-filecommander-mcp@1.7.0` | 1 | 1 | 75 | 6 |
| 4 | `io.github.marin1321_mcp-devtools` | `@oscarmarin/mcp-devtools@1.0.1` | 1 | 1 | 29 | 15 |
| 5 | `io.github.domdomegg_shell-exec-mcp` | `shell-exec-mcp@1.2.0` | 1 | 0 | 1 | 1 |
| 6 | `io.github.hypnosis_docker-mcp-server` | `@hypnosis/docker-mcp-server@2.0.1` | 1 | 0 | 53 | 0 |
| 7 | `io.github.mindstone_mcp-server-browser-automation` | `@mindstone/mcp-server-browser-automation@0.2.4` | 1 | 0 | 15 | 4 |
| 8 | `io.github.Ashutos1997_ffmpeg-mcp-server` | `@ash_j1997/ffmpeg-mcp-server@0.5.0` | 0 | 11 | 36 | 24 |
| 9 | `io.github.Patrizzos_envspeak` | `@patrizzos/envspeak@0.1.0` | 0 | 5 | 18 | 0 |
| 10 | `io.github.ashlrai_webfetch` | `getwebfetch-mcp@0.1.5` | 0 | 2 | 7 | 17 |
| 11 | `io.github.cocaxcode_database-mcp` | `@cocaxcode/database-mcp@0.1.14` | 0 | 2 | 36 | 6 |
| 12 | `io.github.qualienai_qualien-mcp` | `qualien-mcp@0.6.2` | 0 | 2 | 79 | 4 |
| 13 | `io.github.verygoodplugins_mcp-local-wp` | `@verygoodplugins/mcp-local-wp@2.0.0` | 0 | 2 | 0 | 4 |
| 14 | `io.github.msanchezgrice_talkform` | `@talkform/mcp@0.1.0` | 0 | 1 | 0 | 0 |
| 15 | `ai.quorumdb_quorum` | `quorum-mcp-server@4.0.0` | 0 | 0 | 23 | 7 |
| 16 | `ai.spideriq_publish` | `@spideriq/mcp-publish@1.25.0` | 0 | 0 | 796 | 0 |
| 17 | `capital.hove_read-only-local-postgres-mcp-server` | `@hovecapital/read-only-postgres-mcp-server@0.1.0` | 0 | 0 | 3 | 0 |
| 18 | `com.dbconvert_streams` | `@dbconvert/stream-mcp@2.7.3` | 0 | 0 | 2 | 0 |
| 19 | `io.github.AnIayana_high-performance-mcp-server` | `high-performance-mcp-server@0.5.0` | 0 | 0 | 1 | 0 |
| 20 | `io.github.InstaNode-dev_mcp` | `@instanode/mcp@0.7.2` | 0 | 0 | 4 | 0 |
| 21 | `io.github.Keremturker_cmpose` | `@cmpose/mcp@0.8.9` | 0 | 0 | 23 | 7 |
| 22 | `io.github.Lunarwerx_connections` | `connections-mcp@2.253.0` | 0 | 0 | 15 | 0 |
| 23 | `io.github.Rheopyrin_db-access-mcp` | `@rheopyrin/db-access-mcp@0.1.5` | 0 | 0 | 12 | 15 |
| 24 | `io.github.RichardLemmon_agent-team` | `agent-team-mcp@1.5.1` | 0 | 0 | 95 | 0 |
| 25 | `io.github.Shrike-Security_shrike-mcp` | `shrike-mcp@4.1.0` | 0 | 0 | 80 | 0 |
| 26 | `io.github.YawLabs_terraform-cwd-mcp` | `@yawlabs/terraform-cwd-mcp@0.1.2` | 0 | 0 | 24 | 8 |
| 27 | `io.github.aethynio_aethyn-browser-mcp` | `aethyn-browser-mcp@0.1.1` | 0 | 0 | 14 | 5 |
| 28 | `io.github.amol21p_interactive-terminal` | `mcp-interactive-terminal@1.0.7` | 0 | 0 | 10 | 9 |
| 29 | `io.github.antonorlov_mcp-postgres-server` | `mcp-postgres-server@0.3.1` | 0 | 0 | 7 | 0 |
| 30 | `io.github.cheveguerra_sqlite-local-ai-memory` | `sqlite-local-ai-memory@1.5.3` | 0 | 0 | 11 | 1 |
| 31 | `io.github.cyanheads_cern-opendata-mcp-server` | `@cyanheads/cern-opendata-mcp-server@0.3.0` | 0 | 0 | 1 | 34 |
| 32 | `io.github.cyanheads_wikidata-mcp-server` | `@cyanheads/wikidata-mcp-server@0.3.0` | 0 | 0 | 10 | 10 |
| 33 | `io.github.domdomegg_filesystem-mcp` | `filesystem-mcp@1.3.0` | 0 | 0 | 7 | 3 |
| 34 | `io.github.ed-smartass_dbmole-mcp` | `dbmole-mcp@0.2.0` | 0 | 0 | 14 | 26 |
| 35 | `io.github.formfeed-dev_formfeed` | `@formfeed/mcp@0.3.21` | 0 | 0 | 22 | 16 |
| 36 | `io.github.j0hanz_memory-mcp` | `@j0hanz/memory-mcp@1.7.0` | 0 | 0 | 5 | 29 |
| 37 | `io.github.jojo-labs_smart-web` | `smart-web-mcp@1.10.19` | 0 | 0 | 0 | 73 |
| 38 | `io.github.malamutemayhem_chessdotcom` | `@unclick/chessdotcom-mcp@0.1.0` | 0 | 0 | 5 | 0 |
| 39 | `io.github.malamutemayhem_igdb` | `@unclick/igdb-mcp@0.1.0` | 0 | 0 | 17 | 0 |
| 40 | `io.github.malamutemayhem_lichess` | `@unclick/lichess-mcp@0.1.0` | 0 | 0 | 7 | 0 |
| 41 | `io.github.malamutemayhem_radiobrowser` | `@unclick/radiobrowser-mcp@0.1.0` | 0 | 0 | 8 | 0 |
| 42 | `io.github.mindstone_mcp-server-replit-ssh` | `@mindstone/mcp-server-replit-ssh@0.2.2` | 0 | 0 | 27 | 2 |
| 43 | `io.github.mrZedov_backend-investigator` | `@mr.zedov/backend-investigator@1.7.2` | 0 | 0 | 16 | 53 |
| 44 | `io.github.neverinfamous_db-mcp` | `db-mcp@1.0.2` | 0 | 0 | 0 | 0 |
| 45 | `io.github.onlsol_relay-remotify-mcp` | `remotify-mcp@0.6.2` | 0 | 0 | 1 | 0 |
| 46 | `io.github.orifisher2_sqlike-mcp` | `@sqlike/mcp@0.2.3` | 0 | 0 | 0 | 9 |
| 47 | `io.github.sdamarketing_tgcloud-mcp` | `tgcloud-mcp@0.3.3` | 0 | 0 | 18 | 5 |
| 48 | `io.github.sekera-radim_briefgate` | `@briefgate/mcp@0.10.7` | 0 | 0 | 75 | 0 |
| 49 | `io.github.sendsoon_mcp` | `@sendsoon/mcp@0.3.8` | 0 | 0 | 6 | 0 |

## 网关状态（冻结时）

- 冻结前网关共 **102** 个后端 = 本批 100 + 2 个开发/回归固定靶标（`gitmcp`、`interactive-terminal`，不属于第一批）。
- 冻结操作：**删除 51 个失败后端**，保留 49 个成功后端（全部 disabled）+ 2 个固定靶标。
- 删除前已备份网关配置：服务器 `~/mcp_deploy/gateway/data/mcp_settings.json.bak-<时间戳>`。

## 复现 / 重跑

```bash
cd ~/mcpfuzz/prototype && . .venv/bin/activate
mcpfuzz scan --batch <本目录>/targets.txt \
  --batch-name '第一批100个mcp服务-rerun' \
  --gateway http://127.0.0.1:3000 \
  --gateway-user admin --gateway-password '<网关密码，见本机记忆 mcphub-gateway>' --yes
```
