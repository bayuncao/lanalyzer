# FastMCP 迁移说明

## 迁移概述

项目已从旧版MCP实现迁移到使用 [FastMCP](https://github.com/jlowin/fastmcp)。FastMCP是一个功能更强大、更灵活的MCP（Model Context Protocol）框架，提供更好的客户端支持、服务器组合和更多高级功能。

## 已完成的更改

1. **依赖添加**
   - 在`pyproject.toml`中添加了`fastmcp>=2.0.0`作为`[mcp]`可选依赖

2. **MCP服务器实现**
   - 重写了`lanalyzer/mcp/mcp_cmd.py`，使用`FastMCP`替代原有实现
   - 所有工具现在使用`async`实现，支持`Context`参数，可通过上下文进行日志记录和进度报告
   - 创建了全局`mcp`实例，可在其他模块中直接导入使用

3. **包导出更新**
   - 更新了`lanalyzer/mcp/__init__.py`，从`mcp_cmd.py`中导出`mcp`服务器实例
   - 添加了必要的导入检查，确保`fastmcp`依赖已安装

4. **兼容性保障**
   - 保留了`lanalyzer/mcp/server.py`，但添加了弃用警告
   - `MCPServer`类现在是一个兼容层，内部使用`FastMCP`实现

5. **CLI集成**
   - 更新了`lanalyzer/cli/enhanced.py`中的`mcp`子命令，使用新的`FastMCP`实现
   - 命令行接口保持不变，用户可继续使用`lanalyzer mcp run`等命令

6. **文档**
   - 创建了`lanalyzer/mcp/README.md`，说明如何使用基于FastMCP的MCP功能
   - 添加了迁移文档

## 使用新实现的方法

### 命令行

```bash
# 启动MCP服务器
lanalyzer mcp run

# 开发模式
lanalyzer mcp dev

# 安装到Claude Desktop
lanalyzer mcp install --name "Lanalyzer安全分析"
```

### 编程方式

```python
# 导入并运行MCP服务器
from lanalyzer.mcp import mcp_server

# 运行服务器
mcp_server.run()

# 或指定参数
mcp_server.run(transport="sse", host="0.0.0.0", port=9000)
```

## 扩展MCP功能

现在可以使用FastMCP的高级功能扩展Lanalyzer：

1. **添加新工具**：

```python
from lanalyzer.mcp import mcp_server

@mcp_server.tool()
async def my_custom_tool(param1: str, ctx=None):
    if ctx:
        await ctx.info("处理中...")
    return {"result": "完成"}
```

2. **添加资源文件**：

```python
@mcp_server.resource("config://default")
def get_default_config():
    return {"sources": [...], "sinks": [...]}
```

3. **使用提示模板**：

```python
@mcp_server.prompt()
def explain_vulnerability(vuln_info: dict) -> str:
    return f"""
    在 {vuln_info['file_path']} 文件的第 {vuln_info['line']} 行发现了类型为 {vuln_info['rule_name']} 的漏洞。
    这个漏洞的严重性为 {vuln_info['severity']}。
    请分析这个漏洞并解释它的风险以及如何修复。
    """
```

## 注意事项

1. 直接使用`lanalyzer.mcp.server.MCPServer`的代码将收到弃用警告，但目前仍能正常工作
2. 新实现需要Python 3.10或更高版本
3. FastMCP需要通过`pip install lanalyzer[mcp]`或`pip install fastmcp`安装 