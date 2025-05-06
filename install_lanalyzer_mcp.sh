#!/bin/bash
# 使用MCP CLI安装Lanalyzer MCP服务器
# 这个脚本用于在Claude Desktop或其他MCP兼容客户端中安装Lanalyzer MCP服务器

# 确保脚本在出错时退出
set -e

# 脚本路径
SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MCP_PACKAGE="$SCRIPT_PATH/lanalyzer/mcp/mcp_cmd.py"

# 确保MCP命令行模块存在
if [ ! -f "$MCP_PACKAGE" ]; then
    echo "错误: MCP命令模块不存在: $MCP_PACKAGE"
    exit 1
fi

# 检查MCP CLI工具是否已安装
if ! command -v mcp &> /dev/null; then
    echo "正在安装MCP CLI工具..."
    pip install mcp[cli]>=1.7.1
fi

# 安装Lanalyzer MCP依赖
echo "确保Lanalyzer MCP依赖已安装..."
pip install -e ".[mcp]" || pip install -e ".[mcp]"

# 使用MCP CLI安装服务器
echo "正在安装Lanalyzer MCP服务器..."

# 直接安装到Claude Desktop
mcp install "$MCP_PACKAGE" --name "Lanalyzer 安全分析工具" 

echo "Lanalyzer MCP服务器安装成功!"
echo "您现在可以在Claude Desktop或其他支持MCP的工具中使用它。"
echo "也可以通过命令行运行: lanalyzer mcp" 