# gateway 镜像：mcphub 网关 + 补齐两套运行时。
# 目标清单里 82% 是 npm(npx)、18% 是 PyPI(uvx)，所以容器内必须同时有 node/npx 和 uv/uvx。
# mcphub 基础镜像是 node 系(有 npx)，这里补装 uv(带 uvx) + curl/git（命令注入带外回连常用 curl）。
# 不覆盖 mcphub 自身的 ENTRYPOINT/CMD，只加层。
#
# 假设基础镜像是 Debian 系（node:slim 默认如此）。若实测为 Alpine，把 apt-get 换成 apk。
FROM samanhappy/mcphub:latest

USER root

# 补系统依赖（python3 作兜底；uv 的 uvx 也能自行下载受管 Python）
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates git python3 \
 && rm -rf /var/lib/apt/lists/*

# 安装 uv / uvx 到 /usr/local/bin（在 PATH 上，mcphub 拉起 stdio 后端时能直接用）
RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh \
 && uv --version && uvx --version
