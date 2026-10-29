# deploy —— MCP 靶机统一部署框架

在服务器 `/home/ubuntu/mcp_deploy` 下运行。所有靶机按统一约定用 Docker 部署，便于规模化管理。

## 约定

- 每个靶机一个目录 `targets/<id>/`，内含 `meta.json`（必需）和可选的 `Dockerfile`（模板不够用时才写）。
- 容器对外统一在**内部 8000 端口**提供 Streamable HTTP；对外公网端口取 `meta.json` 的 `port`。
- stdio 服务器在容器内用 supergateway/mcp-proxy 包成 HTTP；HTTP 原生服务器直接监听 8000。
- 所有靶机容器 + OOB 采集服务接入同一 docker 网络 `mcpnet`，容器内用 `http://oob:9100/<token>` 回连。

## 目录

```
manifest.json              全局配置（网络名、内存上限、OOB 设置）
targetctl.py               靶机管理工具（纯标准库）
templates/node.Dockerfile  npm 系通用模板（预装 git/curl/supergateway）
templates/python.Dockerfile PyPI 系通用模板（预装 git/curl/mcp-proxy）
infra/oob/                 带外回连采集服务
targets/<id>/meta.json     单个靶机元数据
```

## 常用命令

```bash
python3 targetctl.py list                 # 列出所有靶机及状态
python3 targetctl.py infra-up             # 建网络 + 启动 OOB 采集服务（首次先做）
python3 targetctl.py build <id>           # 构建镜像
python3 targetctl.py start <id>           # 启动容器
python3 targetctl.py reset <id>           # 重置到干净状态
python3 targetctl.py stop  <id>
python3 targetctl.py rm    <id>
```

## 新增一个靶机

1. 在 `targets/` 下建目录（id 建议 = 包名去斜杠 + 版本）。
2. 复制一份 `meta.json` 改字段：`package` / `vuln_version` / `transport` / `start_cmd` / `env` / `port`（端口按 20000 起顺延，勿重复）/ `cve` / `vuln_class` / `hint`。
3. `build` + `start`。模板不够用（需额外系统依赖或特殊启动）时，在该目录放一个 `Dockerfile` 覆盖模板。

## 一次性准备

- 腾讯云安全组放行端口段（如 20000–20100）+ OOB 端口 9100。
- `python3 targetctl.py infra-up` 启动共用的 OOB 采集服务。

## meta.json 字段说明

| 字段 | 含义 |
|---|---|
| `ecosystem` | `npm` 或 `pypi`，决定用哪个模板 |
| `package` / `vuln_version` | 要部署的包与有漏洞的版本 |
| `patched_version` | 修复版本，做对照实验时用 |
| `transport` | `http`（原生）或 `stdio`（需网关包装） |
| `start_cmd` | 容器内启动命令（通过环境变量 START_CMD 执行） |
| `env` | 传给容器的环境变量 |
| `port` | 对外公网端口 |
| `cve` / `ghsa` / `vuln_class` | 漏洞标识与类型 |
| `hint` | 已知的受影响工具/参数/底层程序/示例载荷，供验证与标注参考 |
