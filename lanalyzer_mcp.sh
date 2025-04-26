#!/bin/bash

# 检查是否已安装MCP依赖
if ! pip show fastapi uvicorn pydantic &> /dev/null; then
  echo "安装MCP依赖..."
  pip install lanalyzer[mcp]
fi

# 启动MCP服务器
echo "启动Lanalyzer MCP服务器..."
lanalyzer mcp --host 0.0.0.0 --port 8000 --debug 