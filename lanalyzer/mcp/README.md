# Lanalyzer MCP 服务器

Lanalyzer MCP (Model Context Protocol) 服务器使用 [FastMCP](https://github.com/jlowin/fastmcp) 实现，提供了丰富的代码安全分析功能，可以集成到任何支持 MCP 协议的系统中。

## 安装

确保安装 MCP 相关依赖：

```bash
pip install "lanalyzer[mcp]"
```

或者单独安装 FastMCP：

```bash
pip install fastmcp
```

## 使用方法

### 命令行使用

1. 启动 MCP 服务器：

```bash
# 使用子命令启动 HTTP 服务器
lanalyzer mcp run

# 指定主机和端口
lanalyzer mcp run --host 0.0.0.0 --port 9000
```

2. 开发模式 (包含调试信息和交互式界面)：

```bash
lanalyzer mcp dev
```

3. 将 Lanalyzer MCP 安装到 Claude Desktop：

```bash
lanalyzer mcp install --name "Lanalyzer 安全分析"
```

### 编程方式使用

```python
from lanalyzer.mcp import mcp_server

# MCP 服务器已经配置好所有工具
# 直接运行
mcp_server.run()
```

## 可用的 MCP 工具

Lanalyzer MCP 服务器提供以下工具：

1. `analyze_code` - 分析提供的 Python 代码片段
2. `analyze_file` - 分析本地文件
3. `analyze_path` - 分析目录或多个文件
4. `explain_vulnerabilities` - 解释检测到的漏洞
5. `get_config` - 获取配置内容
6. `validate_config` - 验证配置
7. `create_config` - 创建新配置文件

## 示例

```python
# 使用 MCP 客户端调用 Lanalyzer
from fastmcp import Client

async def analyze_security():
    async with Client("lanalyzer mcp dev") as client:
        # 分析文件
        result = await client.call_tool("analyze_file", {
            "file_path": "/path/to/your/python_file.py"
        })
        
        print(f"发现 {len(result['vulnerabilities'])} 个安全问题")
        
        # 解释漏洞
        if result['vulnerabilities']:
            explanation = await client.call_tool("explain_vulnerabilities", {
                "analysis_file": result['output_path'],
                "format": "markdown"
            })
            print(explanation['explanation'])
```

## 注意事项

1. FastMCP 需要 Python 3.10 或更高版本
2. 要启用 MCP 功能，请确保安装了可选依赖 `lanalyzer[mcp]` 