# 使用官方 Python 镜像作为基础
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    build-essential \
    vim \
    iputils-ping \
    telnet \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /app

# 复制依赖文件
COPY requirements.txt .

# 安装依赖
RUN pip install --no-cache-dir -r requirements.txt

# 复制源代码
COPY . .

# 设置环境变量
ENV JUMPSERVER_API_BASE_URL=${JUMPSERVER_API_BASE_URL}
ENV DEFAULT_ORG_ID=${DEFAULT_ORG_ID}
ENV ADMIN_USERNAME=${ADMIN_USERNAME}
ENV ADMIN_PASSWORD=${ADMIN_PASSWORD}

# 创建日志目录
RUN mkdir -p /app/log/mcp_server

# 暴露端口
EXPOSE 3004

# 启动命令
CMD ["python", "mcp_jumpserver.py"]