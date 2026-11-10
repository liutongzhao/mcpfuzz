#!/bin/sh
# 本地一键：构建三个镜像(linux/amd64) → 打包成一个镜像包(.tar.gz)，scp 到服务器后 docker load 即可。
# 用法：
#   sh build-save.sh                 # tag=latest
#   IMAGE_TAG=v2 sh build-save.sh     # 指定版本号
# 只打 runner（改了扫描器代码、gateway/oob 没变时，包更小）：
#   sh build-save.sh runner
set -eu
cd "$(dirname "$0")"

TAG="${IMAGE_TAG:-latest}"
ONLY="${1:-all}"
export DOCKER_DEFAULT_PLATFORM=linux/amd64   # Mac(arm64) → 服务器(amd64)，必须

echo "==> 构建镜像 (platform=linux/amd64, tag=$TAG)"
IMAGE_TAG="$TAG" docker compose -f docker-compose.yml -f docker-compose.build.yml build

if [ "$ONLY" = "runner" ]; then
  IMAGES="mcpfuzz-runner:$TAG"
  OUT="mcpcells-runner-$TAG.tar.gz"
else
  IMAGES="mcpfuzz-runner:$TAG mcpfuzz-gateway:$TAG mcpfuzz-oob:$TAG"
  OUT="mcpcells-images-$TAG.tar.gz"
fi

echo "==> 打包 → $OUT"
# shellcheck disable=SC2086
docker save $IMAGES | gzip > "$OUT"

echo "==> 完成：$(pwd)/$OUT"
echo "    传服务器：scp $OUT 用户@服务器:~/mcpcells/"
echo "    服务器加载：gunzip -c $OUT | docker load"
