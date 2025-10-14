#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试网络诊断 MCP 服务器功能
"""

import subprocess
import time
import requests
import json

def test_ping_function():
    """测试 ping 功能"""
    print("=== 测试 ping 功能 ===")
    try:
        # 直接测试 ping 命令
        result = subprocess.run(["ping", "-c", "2", "www.baidu.com"], 
                              capture_output=True, text=True, timeout=10)
        print(f"Ping google.com 结果:")
        print(f"返回码: {result.returncode}")
        print(f"输出: {result.stdout[:200]}...")
        print(f"错误: {result.stderr}")
        return True
    except Exception as e:
        print(f"Ping 测试失败: {e}")
        return False

def test_telnet_function():
    """测试 telnet 功能"""
    print("\n=== 测试 telnet 功能 ===")
    try:
        import socket
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex(("www.baidu.com", 80))
        end_time = time.time()
        response_time = round((end_time - start_time) * 1000, 2)
        
        print(f"Telnet www.baidu.com:80 结果:")
        print(f"连接成功: {result == 0}")
        print(f"响应时间: {response_time}ms")
        print(f"错误码: {result}")
        sock.close()
        return True
    except Exception as e:
        print(f"Telnet 测试失败: {e}")
        return False

def test_mcp_server():
    """测试 MCP 服务器"""
    print("\n=== 测试 MCP 服务器 ===")
    try:
        # 检查服务器是否在运行
        response = requests.get("http://localhost:3003/network/api/v1/resource/network://status", timeout=5)
        print(f"服务器状态: {response.status_code}")
        if response.status_code == 200:
            print(f"响应内容: {response.text}")
        return True
    except requests.exceptions.ConnectionError:
        print("MCP 服务器未运行")
        return False
    except Exception as e:
        print(f"MCP 服务器测试失败: {e}")
        return False

def main():
    print("开始测试网络诊断工具...")
    
    # 测试基本功能
    ping_ok = test_ping_function()
    telnet_ok = test_telnet_function()
    server_ok = test_mcp_server()
    
    print("\n=== 测试总结 ===")
    print(f"Ping 功能: {'✓ 正常' if ping_ok else '✗ 异常'}")
    print(f"Telnet 功能: {'✓ 正常' if telnet_ok else '✗ 异常'}")
    print(f"MCP 服务器: {'✓ 运行中' if server_ok else '✗ 未运行'}")
    
    if ping_ok and telnet_ok:
        print("\n网络诊断工具功能正常，可以启动 MCP 服务器使用。")
        print("\n使用方法:")
        print("1. 启动服务器: python mcp_server_linux.py")
        print("2. 通过 HTTP API 调用工具:")
        print("   - Ping: POST http://localhost:3003/network/tools/ping_host")
        print("   - Telnet: POST http://localhost:3003/network/tools/telnet_check")
        print("   - 端口扫描: POST http://localhost:3003/network/tools/network_scan")
    else:
        print("\n部分功能测试失败，请检查系统环境。")

if __name__ == "__main__":
    main()