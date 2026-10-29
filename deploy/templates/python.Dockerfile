# PyPI 系 MCP 服务器通用模板。
# 构建参数：PKG=包名  VER=版本。启动命令由容器环境变量 START_CMD 提供。
# 预装 git/curl 原因同 node 模板；预装 mcp-proxy：stdio 服务器用它包成 Streamable HTTP。
FROM python:3.12-slim
ARG PKG
ARG VER
RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "${PKG}==${VER}" mcp-proxy
EXPOSE 8000
CMD ["sh", "-c", "$START_CMD"]
