#!/bin/bash

# 停止可能正在运行的lanalyzer MCP服务器进程
echo "停止已运行的lanalyzer MCP服务器..."
pkill -f "lanalyzer mcp" || true

# 安装最新代码
echo "更新安装lanalyzer..."
uv pip install -e ".[mcp]"

# 启动MCP服务器
echo "启动lanalyzer MCP服务器..."
lanalyzer mcp run --host 0.0.0.0 --port 8000 --debug 