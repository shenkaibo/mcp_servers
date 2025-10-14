from fastmcp import FastMCP
import subprocess
import socket
import time
import asyncio
 
# 创建MCP服务器实例，指定端口
mcp = FastMCP("Network Diagnostic Service",host="0.0.0.0",port=3003)
 
 
@mcp.tool()
def ping_host(host: str, count: int = 4) -> dict:
    """Ping指定主机并返回结果"""
    try:
        # 执行ping命令
        result = subprocess.run(
            ["ping", "-c", str(count), host],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        return {
            "host": host,
            "success": result.returncode == 0,
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except subprocess.TimeoutExpired:
        return {
            "host": host,
            "success": False,
            "error": "Ping操作超时",
            "return_code": -1
        }
    except Exception as e:
        return {
            "host": host,
            "success": False,
            "error": str(e),
            "return_code": -1
        }
 
 
@mcp.tool()
def telnet_check(host: str, port: int, timeout: int = 10) -> dict:
    """检查指定主机的端口连通性"""
    start_time = time.time()
    try:
        # 创建socket连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # 尝试连接
        result = sock.connect_ex((host, port))
        end_time = time.time()
        response_time = round((end_time - start_time) * 1000, 2)  # 毫秒
        
        sock.close()
        
        return {
            "host": host,
            "port": port,
            "success": result == 0,
            "response_time_ms": response_time,
            "error_code": result,
            "message": "端口连通" if result == 0 else f"连接失败，错误码: {result}"
        }
    except Exception as e:
        end_time = time.time()
        response_time = round((end_time - start_time) * 1000, 2)
        return {
            "host": host,
            "port": port,
            "success": False,
            "response_time_ms": response_time,
            "error": str(e)
        }
 
 
@mcp.tool()
def network_scan(host: str, ports: list = [22, 80, 443, 8080]) -> dict:
    """扫描指定主机的多个端口"""
    results = []
    for port in ports:
        result = telnet_check(host, port, timeout=5)
        results.append(result)
        # 短暂延迟，避免过于频繁的连接
        time.sleep(0.1)
    
    open_ports = [r for r in results if r["success"]]
    closed_ports = [r for r in results if not r["success"]]
    
    return {
        "host": host,
        "scan_results": results,
        "open_ports": [r["port"] for r in open_ports],
        "closed_ports": [r["port"] for r in closed_ports],
        "summary": {
            "total_ports_scanned": len(ports),
            "open_ports_count": len(open_ports),
            "closed_ports_count": len(closed_ports)
        }
    }
 
 
@mcp.resource("network://tools")
def get_available_tools() -> list:
    """获取可用的网络诊断工具列表"""
    return ["ping", "telnet", "network_scan"]
 
 
@mcp.resource("network://status")
def get_service_status() -> dict:
    """获取服务状态信息"""
    return {
        "service": "Network Diagnostic Service",
        "status": "running",
        "version": "1.0.0",
        "available_tools": ["ping", "telnet", "network_scan"],
        "timestamp": time.time()
    }
 

async def main():
    # 使用HTTP传输方式启动服务器
    await mcp.run_streamable_http_async(None, None, None, "/network")

if __name__ == "__main__":
    asyncio.run(main())