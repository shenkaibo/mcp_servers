# 网络诊断 MCP 服务器

基于 FastMCP 实现的网络诊断工具服务器，支持 ping、telnet 和端口扫描功能。

## 功能特性

- **Ping 检测**: 测试主机连通性
- **Telnet 检查**: 检测端口连通性
- **端口扫描**: 批量扫描多个端口状态
- **RESTful API**: 通过 HTTP 接口调用工具

## 安装依赖

### 方式一：直接运行
```bash
pip install fastmcp
```

### 方式二：Docker 容器运行
```bash
# 构建镜像
docker build -t network-diagnostic-mcp:latest .

# 运行容器
docker run -d --name network-diagnostic -p 3003:3003 network-diagnostic-mcp:latest

# 或使用 docker-compose
docker-compose up -d
```

## 启动服务器

### 直接运行
```bash
python mcp_server_linux.py
```

### Docker 运行

### 前提条件
确保 Docker 守护进程正在运行：
```bash
# 检查 Docker 状态
docker --version
docker ps

# 如果 Docker 未运行，请启动 Docker Desktop 或 OrbStack
```

### 构建和运行
```bash
# 使用构建脚本
./build.sh
./run.sh

# 或直接运行
docker-compose up -d

# 或手动构建和运行
docker build -t network-diagnostic-mcp:latest .
docker run -d --name network-diagnostic -p 3003:3003 network-diagnostic-mcp:latest
```

服务器将在 `http://localhost:3003` 启动，API 路径为 `/network`

### 验证部署
```bash
# 检查容器状态
docker ps

# 查看日志
docker logs network-diagnostic

# 测试 API
curl http://localhost:3003/network/resources/network://status
```

## API 接口

### 1. Ping 主机

**端点**: `POST /network/tools/ping_host`

**参数**:
```json
{
  "host": "google.com",
  "count": 4
}
```

**示例响应**:
```json
{
  "host": "google.com",
  "success": true,
  "return_code": 0,
  "stdout": "PING google.com...",
  "stderr": ""
}
```

### 2. Telnet 端口检查

**端点**: `POST /network/tools/telnet_check`

**参数**:
```json
{
  "host": "google.com",
  "port": 80,
  "timeout": 10
}
```

**示例响应**:
```json
{
  "host": "google.com",
  "port": 80,
  "success": true,
  "response_time_ms": 45.23,
  "error_code": 0,
  "message": "端口连通"
}
```

### 3. 网络扫描

**端点**: `POST /network/tools/network_scan`

**参数**:
```json
{
  "host": "example.com",
  "ports": [22, 80, 443, 8080]
}
```

**示例响应**:
```json
{
  "host": "example.com",
  "scan_results": [...],
  "open_ports": [80, 443],
  "closed_ports": [22, 8080],
  "summary": {
    "total_ports_scanned": 4,
    "open_ports_count": 2,
    "closed_ports_count": 2
  }
}
```

### 4. 获取可用工具

**端点**: `GET /network/resources/network://tools`

**响应**:
```json
["ping", "telnet", "network_scan"]
```

### 5. 服务状态

**端点**: `GET /network/resources/network://status`

**响应**:
```json
{
  "service": "Network Diagnostic Service",
  "status": "running",
  "version": "1.0.0",
  "available_tools": ["ping", "telnet", "network_scan"],
  "timestamp": 1697280000
}
```

## 使用示例

### cURL 示例

```bash
# Ping 测试
curl -X POST http://localhost:3003/network/tools/ping_host \
  -H "Content-Type: application/json" \
  -d '{"host": "google.com", "count": 4}'

# Telnet 测试
curl -X POST http://localhost:3003/network/tools/telnet_check \
  -H "Content-Type: application/json" \
  -d '{"host": "google.com", "port": 80, "timeout": 5}'

# 端口扫描
curl -X POST http://localhost:3003/network/tools/network_scan \
  -H "Content-Type: application/json" \
  -d '{"host": "github.com", "ports": [22, 80, 443]}'
```

### Python 客户端示例

```python
import requests
import json

def ping_host(host, count=4):
    response = requests.post(
        "http://localhost:3003/network/tools/ping_host",
        json={"host": host, "count": count}
    )
    return response.json()

def telnet_check(host, port, timeout=10):
    response = requests.post(
        "http://localhost:3003/network/tools/telnet_check",
        json={"host": host, "port": port, "timeout": timeout}
    )
    return response.json()

# 使用示例
result = ping_host("google.com")
print(f"Ping 结果: {result['success']}")

result = telnet_check("google.com", 80)
print(f"端口状态: {result['success']}")
```

## 安全注意事项

- 该服务运行在本地网络，请勿暴露到公网
- 端口扫描功能可能被某些网络设备视为恶意行为
- 建议在生产环境中添加认证和授权机制

## 故障排除

1. **权限问题**: 确保有执行 ping 命令的权限
2. **端口占用**: 如果 3003 端口被占用，修改代码中的端口号
3. **网络限制**: 某些网络环境可能限制 ICMP 或端口扫描

## 开发说明

基于 FastMCP 框架开发，支持 MCP (Model Context Protocol) 标准，可以与其他 MCP 客户端集成使用。