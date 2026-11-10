# deploy/cells —— 大规模批量检测单元（docker-compose）

把「一次检测需要的全套」缩小成一个独立 docker-compose 单元（一份 **cell**），照着批次清单
戳出任意多份、分散到多台机器并行跑。**每份 cell 完全隔离、互不打扰，彼此只有「扫哪些目标」这份清单不同。**

> 用途：在**全网搜集的 MCP**（`verified_call_ok.jsonl`，8086 个已验证能响应调用的服务）上做规模化黑盒检测 + 生态测量。

## 一份 cell 里有什么

| 服务 | 作用 |
|---|---|
| `gateway` | 自己的 mcphub 网关（mcphub + node/npx + uv/uvx）。按本批清单把目标当 stdio 后端拉起 |
| `oob` | 带外回连采集器。命令注入/SSRF 的确认通道，走 cell 内网 `http://oob:9100` |
| `runner` | mcpfuzz 扫描器 + `provision.py`（源码已烤进镜像）。先灌清单进网关，再 `mcpfuzz scan --batch` 挨个扫 |

三者同处本 cell 的隔离网络，靠 `-p <批次名>` 区分，彼此不串台。

## 分发方式：本地打镜像 → 传镜像包 → 服务器 load

镜像**自包含**（扫描器源码 + `llm_config.py` 都烤进去了），**服务器上不需要任何源码/仓库**。
以后本地改了代码，重新 build/save、把新镜像包传上去 load 即可。

```
本地(Mac)                                服务器(Linux amd64)
  build-save.sh  ──► mcpcells-images-*.tar.gz  ──scp──►  docker load
                                                          docker compose up
```

> ⚠️ 本机 arm64、服务器 amd64，所以 `build-save.sh` 固定用 `--platform linux/amd64` 构建；
> 镜像包含密钥，**只在可信服务器上 load，别推公开仓库**。

## 用法

### 一、本地：打镜像 + 打包（改了代码就重来一次）

```bash
cd deploy/cells
sh build-save.sh                 # 构建三镜像(amd64) → mcpcells-images-latest.tar.gz
# 只改了扫描器代码、网关/oob 没变时，可只打 runner（包更小）：
sh build-save.sh runner          # → mcpcells-runner-latest.tar.gz
```

### 二、传到服务器 + 加载（每台机一次）

```bash
scp mcpcells-images-latest.tar.gz docker-compose.yml .env.example 用户@服务器:~/mcpcells/
# 服务器上：
cd ~/mcpcells
gunzip -c mcpcells-images-latest.tar.gz | docker load
cp .env.example .env             # 按需改网关账号密码
mkdir -p batches results
```

> 服务器端只需这几样：镜像包、`docker-compose.yml`、`.env`、`batches/`、`results/`。**没有源码。**

### 三、服务器：跑批次

```bash
# 1. 把你切好的清单丢进 batches/，命名成 batch-001.jsonl
#    （= verified_call_ok.jsonl 的行子集，字段原样，见下「批次清单」）
# 2. 起它（起服务即自动开跑）。第一层大模型(ai-pixel)的 key 每批不同，按批注入：
PIXEL_API_KEY=sk-本批的key BATCH=batch-001 docker compose -p batch-001 up -d
# 3. 看进度：
docker compose -p batch-001 logs -f runner
```

多开几份就把 `batch-001` 换成 `batch-002`、`batch-003`…**各自带上本批的 `PIXEL_API_KEY`**
（各自独立、互不打扰）。第二/三层大模型(deepseek / apikey.fan)统一、已烤进镜像，不用配。

> 大模型三层故障切换：① ai-pixel（key 按批注入 `PIXEL_API_KEY`）→ 失败切 ② deepseek → 再失败切
> ③ apikey.fan。某层限流/报错/超时自动顶下一层，三层全挂才暂停整批（`--resume` 可续跑）。

### 四、续跑 / 收工 / 汇总

```bash
# 崩了/重启：再 up，自动 --resume 续跑（续跑同样要带本批的 PIXEL_API_KEY）
PIXEL_API_KEY=sk-本批的key BATCH=batch-001 docker compose -p batch-001 up -d
BATCH=batch-001 docker compose -p batch-001 down -v   # 收工清理本 cell（down 不需要 key）
```

> 汇总用 `collect.py`：它是本地分析脚本（在仓库里，不进镜像）。把各服务器的 `results/` 拉回本地后，
> `python3 collect.py results/` 汇总出一张表 + 部署成功率。

## 批次清单：格式 + 放哪（你负责切分）

- **格式**：直接是 `verified_call_ok.jsonl` 的**行子集**，一行一个 JSON，字段原样。至少要有 `name` + `launch`
  （`registryType`/`identifier`/`tool_names`/`tools_count` 可选，用于结果回溯与部署校验）。示例见 `batches/sample.jsonl`。
- **放这里**：服务器 `~/mcpcells/batches/<批次名>.jsonl`
- **起这份**：`BATCH=<批次名> docker compose -p <批次名> up -d`
- **结果出这里**：`~/mcpcells/results/<批次名>/`

你只需 `split` 大文件 + 把分片丢进 `batches/`，不用做任何格式转换。

## 批量检测流程（`up` 之后全自动）

```
① 起 3 个容器：gateway(mcphub) + oob + runner
② runner 等网关就绪 → 登录 → 把 batch-001.jsonl 整批清单灌进网关（provision.py）
③ 挨个目标循环（mcpfuzz scan --batch）：
      enable  → 网关现场 npx/uvx 拉起这个 MCP（首次联网装包）
      等就绪  → connected 且 tools>0 才算起来
        ├ 起来了   → 推 sink → 发载荷 → 判定 → 写 findings/report
        └ tools=0 → 记一条"部署失败"，跳下一个（不崩，是测量分母的一部分）
      disable → 停掉这个 MCP 释放资源
④ 整批跑完 → runner 退出；产物全在 results/batch-001/
```

中途挂了不用管：网关被注入载荷打挂会自动重启，扫描器 `--resume` 从断点续跑，已扫不重复、不丢。

## 产物（results/<批次名>/）

- `namemap.json` —— 网关后端名 → 原始身份（name/identifier/launch/期望工具）。
- `<批次名>/batch_summary.{json,md}` —— 每个目标的结论计数 / 失败原因。
- `<批次名>/_done.jsonl` —— 断点账本。
- `<批次名>/<每次运行>/` —— `findings.json` / `report.md` / `catalog.json` / `run.log` / `events.jsonl`。

## 本地已验证 / 服务器上还要确认的点

**本地冒烟已跑通（2026-11-07，Mac arm64）**：三镜像构建、cell 启动、网关鉴权、provision 灌清单、scan 启动+enable 全通；
本地唯一卡点是 Mac 的 VPN/代理把容器内 npm/PyPI 下载限速/掐断（`198.18.x.x` 假 IP），导致目标包拉不下来——
**是本机网络问题，不是 cell 问题**。真实服务器按下面配好镜像源即可。

**网关账号密码**：已由 compose 的 `ADMIN_PASSWORD`（= `GATEWAY_PASSWORD`，默认 admin123）定死，首启自动建 admin；
**换密码要重建网关容器**（`down` 后 `up`）让它重新首启才生效。

**服务器上还要确认 / 可能要调：**
1. **目标包下载源**（大概率要配）：国内服务器拉 npm/PyPI 慢或断时，在 `.env` 里解开
   `NPM_REGISTRY=https://registry.npmmirror.com` 和 `UV_INDEX=https://pypi.tuna.tsinghua.edu.cn/simple`，
   否则 npx/uvx 冷启动会卡住 → 目标被误判"部署失败"。
2. **MCP 端点鉴权**：`/mcp/{server}` 默认要 `Authorization: Bearer`。`provision.py` 会尝试铸 key 写进 `bearer.txt`、
   扫描时自动带上；铸不出会回退登录 JWT（本地日志见"回退登录 JWT"，尚未验证该 JWT 对 MCP 端点是否够用）。
   **若日志里 fetch_catalog 一直 401**，把 mcphub 版本和 `/api/auth/keys` 响应发我来调。
3. **工具输出压缩**：mcphub 若默认开启会截断回显 → 漏报。抽查一个 `run.log`，若回显被截断需关掉它
   （暂未脚本化，确认 `systemConfig` 里的键名后下一轮补进）。

## 已知边界

- **冷启动预算**：`wait_ready` 上限约 180s，极少数装包特别慢的包可能被误判"部署失败"。
- **磁盘**：npx/uvx 缓存会在 gateway 容器里涨；资源不紧张无需管，`down -v` 即清。
- **自毁恢复**：命令/代码注入载荷会在 gateway 容器里真执行(root)；gateway `restart: unless-stopped` 自动拉回，
  runner `restart: on-failure` + `--resume` 续跑，cell 之间隔离、一份炸不牵连别份。
