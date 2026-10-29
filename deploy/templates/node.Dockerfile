# npm 系 MCP 服务器通用模板。
# 构建参数：PKG=包名  VER=版本。启动命令由容器环境变量 START_CMD 提供（见 targetctl.py / meta.json）。
# 预装 git/curl：很多服务器会包装 git，命令注入的带外回连载荷常用 curl。
# 预装 supergateway：stdio 服务器用它包成 Streamable HTTP。
FROM node:20-slim
ARG PKG
ARG VER
RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN npm install -g "${PKG}@${VER}" supergateway
EXPOSE 8000
CMD ["sh", "-c", "$START_CMD"]
