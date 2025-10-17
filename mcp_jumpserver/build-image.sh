#!/bin/bash

# 设置镜像名称和标签
IMAGE_NAME="mcp-jumpserver"
VERSION="1.0.0"
TAG="${IMAGE_NAME}:${VERSION}"

# 构建Docker镜像
echo "Building Docker image ${TAG}..."
docker build -t ${TAG} .

# 检查构建是否成功
if [ $? -eq 0 ]; then
    echo "Docker image built successfully: ${TAG}"
    echo "You can now run the container using:"
    echo "  docker run -p 3004:3004 ${TAG}"
else
    echo "Failed to build Docker image"
    exit 1
fi