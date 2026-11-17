# runner 镜像：calchas 扫描器(源码烤进镜像) + 灌清单胶水(provision.py)。
# 【自包含】——服务器上不需要任何源码，load 镜像即可跑。
# 构建上下文 = 仓库根（见 docker-compose.build.yml 的 context: ../..），所以下面 COPY 路径相对仓库根。
# 注意：COPY prototype 会把本地 prototype/calchas/llm_config.py(含密钥) 一起烤进镜像——
#       所以镜像/镜像包是私密的，只在可信服务器上 load，别推公开仓库。
#
# 依赖策略：只钉死 5 个直接依赖到「本地能跑的 venv」里那套能协同的版本；传递依赖(pydantic_core 等)
# 让 pip 按 linux/当前 Python 自己挑有 wheel 的版本——既避开松约束解析冲突，又避开太新 Python 没 linux 轮子。
# 基础镜像用成熟的 3.12（wheel 齐全）。换依赖时：在 venv 里看新版本号，同步下面这行。
FROM python:3.12-slim

# 装 curl：LLM 客户端(llm_failover._curl_one)用 subprocess 调 curl 发补全请求
# （故意不用 python urllib——该中转的 SSL 对 urllib 会断，见 llmclient.py 注释）。
# slim 基镜像不带 curl，漏装会导致 runner 内所有 LLM 调用失败、全程降级成无模型兜底（假跑）。
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# 用国内镜像源（清华）装依赖——pypi.org 在国内 SSL 常被打断(UNEXPECTED_EOF)，会被 pip 误报成
# "没有满足的版本/ResolutionImpossible"。换镜像源后稳定。--retries/--timeout 再兜一层抖动。
RUN pip install --no-cache-dir \
      -i https://pypi.tuna.tsinghua.edu.cn/simple \
      --retries 5 --timeout 60 \
      "mcp==1.30.0" \
      "rich==15.0.0" \
      "langgraph==1.2.19" \
      "langchain-mcp-adapters==0.3.2" \
      "langchain-openai==1.7.3"

# 烤进扫描器源码 + 胶水脚本（路径相对仓库根；.venv/runs/out 已由根 .dockerignore 排除）
COPY prototype /app/prototype
COPY deploy/cells/provision.py /app/provision.py
COPY deploy/cells/images/runner/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENV PYTHONPATH=/app/prototype \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /work
ENTRYPOINT ["/app/entrypoint.sh"]
