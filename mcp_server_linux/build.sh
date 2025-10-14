#!/bin/bash

# 构建 Docker 镜像
echo "构建网络诊断 MCP 服务器 Docker 镜像..."
docker build -t network-diagnostic-mcp:latest .

echo "构建完成！"
echo "运行容器: docker run -p 3003:3003 network-diagnostic-mcp:latest"
echo "或使用 docker-compose: docker-compose up -d"