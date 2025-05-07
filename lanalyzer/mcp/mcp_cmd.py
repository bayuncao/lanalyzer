#!/usr/bin/env python
"""
MCP服务器命令行入口点，使用FastMCP实现。
提供lanalyzer中的Model Context Protocol (MCP)功能。
"""

import os
import sys
import logging
import click
from typing import Optional, Dict, Any

try:
    # 导入FastMCP核心组件
    from fastmcp import FastMCP, Context
except ImportError:
    raise ImportError(
        "FastMCP dependency not found. "
        "Please install with `pip install lanalyzer[mcp]` "
        "or `pip install fastmcp`"
    )

from lanalyzer.__version__ import __version__
from lanalyzer.mcp.handlers import LanalyzerMCPHandler
from lanalyzer.mcp.models import (
    AnalysisRequest,
    FileAnalysisRequest,
    ExplainVulnerabilityRequest,
    ConfigurationRequest,
)


# 创建FastMCP实例
def create_mcp_server(debug: bool = False) -> FastMCP:
    """
    创建FastMCP服务器实例

    Args:
        debug: 是否启用调试模式

    Returns:
        FastMCP: 服务器实例
    """
    # 配置日志级别
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # 查看FastMCP版本
    try:
        fastmcp_version = __import__("fastmcp").__version__
        logging.info(f"FastMCP版本: {fastmcp_version}")
    except (ImportError, AttributeError):
        logging.warning("无法确定FastMCP版本")
        fastmcp_version = "未知"

    # 创建FastMCP实例 - 针对2.2.8版本兼容性移除部分参数
    mcp = FastMCP(
        "Lanalyzer",
        title="Lanalyzer - Python污点分析工具",
        description="Lanalyzer的MCP服务器，提供Python代码的污点分析功能，用于检测安全漏洞。",
        version=__version__,
        debug=debug,
    )

    # 创建处理器实例
    handler = LanalyzerMCPHandler(debug=debug)

    # 在调试模式下启用请求日志
    if debug:

        @mcp.middleware
        async def log_requests(request, call_next):
            """记录请求和响应的中间件"""
            logging.debug(f"接收到请求: {request.method} {request.url}")
            try:
                if request.method == "POST":
                    body = await request.json()
                    logging.debug(f"请求体: {body}")
            except Exception as e:
                logging.debug(f"无法解析请求体: {e}")

            response = await call_next(request)
            return response

    @mcp.tool()
    async def analyze_code(
        code: str, file_path: str, config_path: str, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        分析提供的Python代码中的安全漏洞

        Args:
            code: 要分析的Python代码
            file_path: 代码的文件路径（用于报告）
            config_path: 配置文件路径（必填）
            ctx: MCP上下文

        Returns:
            分析结果，包含检测到的漏洞信息
        """
        # 记录原始参数，帮助调试
        logging.debug(
            f"analyze_code原始参数: code=<省略>, file_path={file_path}, config_path={config_path}"
        )

        # 处理可能的嵌套参数结构
        actual_file_path = file_path
        actual_config_path = config_path
        actual_code = code

        # 嵌套参数处理
        if isinstance(config_path, dict) and not isinstance(code, str):
            logging.warning(f"检测到嵌套参数结构: {config_path}")

            # 尝试从嵌套结构中提取各参数
            if "file_path" in config_path and isinstance(config_path["file_path"], str):
                actual_file_path = config_path["file_path"]
                logging.warning(f"从嵌套结构中提取file_path: {actual_file_path}")

            if "config_path" in config_path and isinstance(
                config_path["config_path"], str
            ):
                actual_config_path = config_path["config_path"]
                logging.warning(f"从嵌套结构中提取config_path: {actual_config_path}")

            if "code" in config_path and isinstance(config_path["code"], str):
                actual_code = config_path["code"]
                logging.warning("从嵌套结构中提取code")

            # 如果找不到有效的code
            if not isinstance(actual_code, str):
                error_msg = "无法从请求中提取有效的code参数"
                if ctx:
                    await ctx.error(error_msg)
                return {"success": False, "errors": [error_msg]}

        if ctx:
            await ctx.info(f"开始分析代码，文件路径: {actual_file_path}")
            await ctx.info(f"使用配置文件: {actual_config_path}")

        # 参数验证
        if not isinstance(actual_config_path, str):
            error_msg = f"配置路径必须是字符串，收到: {type(actual_config_path)}"
            if ctx:
                await ctx.error(error_msg)
            return {"success": False, "errors": [error_msg]}

        if not isinstance(actual_file_path, str):
            error_msg = f"文件路径必须是字符串，收到: {type(actual_file_path)}"
            if ctx:
                await ctx.error(error_msg)
            return {"success": False, "errors": [error_msg]}

        request = AnalysisRequest(
            code=actual_code, file_path=actual_file_path, config_path=actual_config_path
        )
        result = await handler.handle_analysis_request(request)

        if ctx and result.vulnerabilities:
            await ctx.warning(f"检测到 {len(result.vulnerabilities)} 个潜在漏洞")

        return result.model_dump()

    @mcp.tool()
    async def analyze_file(
        file_path: str, config_path: str, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        分析指定文件路径的Python代码

        Args:
            file_path: 要分析的Python文件路径
            config_path: 配置文件路径（必填）
            ctx: MCP上下文

        Returns:
            分析结果，包含检测到的漏洞信息
        """
        # 记录原始参数，帮助调试
        logging.debug(
            f"analyze_file原始参数: file_path={file_path}, config_path={config_path}"
        )

        # 处理嵌套参数情况
        # 当客户端错误地发送了嵌套的参数结构时进行修正
        actual_file_path = file_path
        actual_config_path = config_path
        is_nested_params = False

        # 如果config_path是字典而不是字符串，尝试提取正确的参数
        if isinstance(config_path, dict):
            is_nested_params = True
            logging.warning(f"收到嵌套的参数结构: {config_path}")

            # 尝试从config_path字典中提取file_path
            if "file_path" in config_path and isinstance(config_path["file_path"], str):
                actual_file_path = config_path["file_path"]
                logging.warning(f"从嵌套结构中提取file_path: {actual_file_path}")

            # 尝试从config_path字典中提取config_path
            if "config_path" in config_path and isinstance(
                config_path["config_path"], str
            ):
                actual_config_path = config_path["config_path"]
                logging.warning(f"从嵌套结构中提取config_path: {actual_config_path}")

            # 如果仍然找不到有效的file_path
            if actual_file_path != file_path and not isinstance(actual_file_path, str):
                # 提供详细的错误信息和正确的请求格式示例
                error_msg = """
无法从请求中提取有效的file_path参数。
您的请求格式有误。正确的请求格式应该是：

{
  "method": "tools/call",
  "params": {
    "name": "analyze_file",
    "arguments": {
      "file_path": "/path/to/your/file.py",
      "config_path": "/path/to/your/config.json"
    }
  }
}

但您发送的请求似乎使用了嵌套的参数结构，如:

{
  "method": "tools/call",
  "params": {
    "name": "analyze_file",
    "arguments": {
      "config_path": {
        "file_path": "...",
        "config_path": "..."
      }
    }
  }
}

请修正您的请求格式，确保参数是顶层键值对。
"""
                if ctx:
                    await ctx.error(error_msg)
                return {"success": False, "errors": [error_msg]}

        if ctx:
            await ctx.info(f"开始分析文件: {actual_file_path}")
            await ctx.info(f"使用配置文件: {actual_config_path}")

            # 如果是嵌套参数，提供警告
            if is_nested_params:
                await ctx.warning(
                    """
注意: 检测到嵌套参数结构。虽然系统尝试进行修正，但这不是标准格式。请更新您的客户端以使用正确的参数格式:
- file_path 和 config_path 应该是顶层参数，而不是嵌套的
"""
                )

        # 记录处理后的参数，方便调试
        logging.debug(
            f"analyze_file处理后参数: file_path={actual_file_path}, config_path={actual_config_path}"
        )

        # 确保配置路径是字符串
        if not isinstance(actual_config_path, str):
            error_msg = f"配置路径必须是字符串，收到: {type(actual_config_path)}"
            if ctx:
                await ctx.error(error_msg)
            return {"success": False, "errors": [error_msg]}

        # 确保文件路径是字符串
        if not isinstance(actual_file_path, str):
            error_msg = f"文件路径必须是字符串，收到: {type(actual_file_path)}"
            if ctx:
                await ctx.error(error_msg)
            return {"success": False, "errors": [error_msg]}

        result = await handler.handle_file_analysis_request(
            actual_file_path, actual_config_path
        )

        if ctx and result.vulnerabilities:
            await ctx.warning(f"检测到 {len(result.vulnerabilities)} 个潜在漏洞")

        return result.model_dump()

    @mcp.tool()
    async def analyze_path(
        target_path: str,
        config_path: str,
        output_path: Optional[str] = None,
        ctx: Context = None,
    ) -> Dict[str, Any]:
        """
        分析目录或文件路径中的Python代码

        Args:
            target_path: 目标文件或目录路径
            config_path: 配置文件路径（必填）
            output_path: 可选的分析结果输出路径
            ctx: MCP上下文

        Returns:
            分析结果，包含检测到的漏洞信息
        """
        # 记录原始参数
        logging.debug(
            f"analyze_path原始参数: target_path={target_path}, config_path={config_path}, output_path={output_path}"
        )

        # 处理嵌套参数结构
        actual_target_path = target_path
        actual_config_path = config_path
        actual_output_path = output_path

        # 如果config_path是字典而不是字符串，尝试提取正确的参数
        if isinstance(config_path, dict):
            logging.warning(f"收到嵌套的参数结构: {config_path}")

            # 尝试从嵌套结构中提取参数
            if "target_path" in config_path and isinstance(
                config_path["target_path"], str
            ):
                actual_target_path = config_path["target_path"]
                logging.warning(f"从嵌套结构中提取target_path: {actual_target_path}")

            if "config_path" in config_path and isinstance(
                config_path["config_path"], str
            ):
                actual_config_path = config_path["config_path"]
                logging.warning(f"从嵌套结构中提取config_path: {actual_config_path}")

            if "output_path" in config_path and (
                isinstance(config_path["output_path"], str)
                or config_path["output_path"] is None
            ):
                actual_output_path = config_path["output_path"]
                logging.warning(f"从嵌套结构中提取output_path: {actual_output_path}")

            # 检查必要参数
            if not isinstance(actual_target_path, str):
                error_msg = "无法从请求中提取有效的target_path参数"
                if ctx:
                    await ctx.error(error_msg)
                return {"success": False, "errors": [error_msg]}

        if ctx:
            await ctx.info(f"开始分析路径: {actual_target_path}")
            await ctx.info(f"使用配置文件: {actual_config_path}")

        # 参数验证
        if not isinstance(actual_config_path, str):
            error_msg = f"配置路径必须是字符串，收到: {type(actual_config_path)}"
            if ctx:
                await ctx.error(error_msg)
            return {"success": False, "errors": [error_msg]}

        if actual_output_path is not None and not isinstance(actual_output_path, str):
            error_msg = f"输出路径必须是字符串或空值，收到: {type(actual_output_path)}"
            if ctx:
                await ctx.error(error_msg)
            return {"success": False, "errors": [error_msg]}

        request = FileAnalysisRequest(
            target_path=actual_target_path,
            config_path=actual_config_path,
            output_path=actual_output_path,
        )

        # 对于大型分析，报告进度
        if ctx:
            await ctx.info("正在收集目标文件...")

        result = await handler.handle_file_path_analysis(request)

        if ctx and result.vulnerabilities:
            await ctx.warning(f"检测到 {len(result.vulnerabilities)} 个潜在漏洞")

        return result.model_dump()

    @mcp.tool()
    async def explain_vulnerabilities(
        analysis_file: str,
        format: str = "text",
        level: str = "detailed",
        ctx: Context = None,
    ) -> Dict[str, Any]:
        """
        解释分析结果中的漏洞

        Args:
            analysis_file: 分析结果文件路径
            format: 输出格式（text或markdown）
            level: 详细程度（brief或detailed）
            ctx: MCP上下文

        Returns:
            漏洞解释结果
        """
        if ctx:
            await ctx.info(f"正在解释漏洞，文件: {analysis_file}")

        request = ExplainVulnerabilityRequest(
            analysis_file=analysis_file, format=format, level=level
        )
        result = await handler.explain_vulnerabilities(request)

        if ctx:
            await ctx.info(f"解释了 {result.vulnerabilities_count} 个漏洞")

        return result.model_dump()

    @mcp.tool()
    async def get_config(
        config_path: Optional[str] = None, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        获取配置文件内容

        Args:
            config_path: 配置文件路径，默认使用内置配置
            ctx: MCP上下文

        Returns:
            配置内容和操作状态
        """
        if ctx:
            config_desc = config_path if config_path else "默认配置"
            await ctx.info(f"正在获取配置: {config_desc}")

        request = ConfigurationRequest(operation="get", config_path=config_path)
        result = await handler.handle_configuration_request(request)
        return result.model_dump()

    @mcp.tool()
    async def validate_config(
        config_data: Dict[str, Any] = None,
        config_path: Optional[str] = None,
        ctx: Context = None,
    ) -> Dict[str, Any]:
        """
        验证配置内容

        Args:
            config_data: 要验证的配置数据
            config_path: 可选配置文件路径（如果提供，将从文件读取）
            ctx: MCP上下文

        Returns:
            验证结果
        """
        if ctx:
            await ctx.info("正在验证配置...")

        request = ConfigurationRequest(
            operation="validate", config_path=config_path, config_data=config_data
        )
        result = await handler.handle_configuration_request(request)

        if ctx:
            if result.success:
                await ctx.info("配置验证成功")
            else:
                await ctx.error("配置验证失败")

        return result.model_dump()

    @mcp.tool()
    async def create_config(
        config_data: Dict[str, Any],
        config_path: Optional[str] = None,
        ctx: Context = None,
    ) -> Dict[str, Any]:
        """
        创建新的配置文件

        Args:
            config_data: 配置数据
            config_path: 可选的输出文件路径
            ctx: MCP上下文

        Returns:
            创建操作结果
        """
        if ctx:
            path_info = f"，保存到: {config_path}" if config_path else ""
            await ctx.info(f"正在创建配置{path_info}")

        request = ConfigurationRequest(
            operation="create", config_path=config_path, config_data=config_data
        )
        result = await handler.handle_configuration_request(request)

        if ctx and result.success:
            await ctx.info("配置创建成功")

        return result.model_dump()

    return mcp


# 创建全局MCP服务器实例
mcp = create_mcp_server()

# 为兼容性提供别名，FastMCP>=2.2会查找名为"server"的变量
mcp_server = mcp
server = mcp


# 添加工具函数调试装饰器，在调试模式下使用
def debug_tool_args(func):
    """记录工具函数的参数，用于调试"""

    async def wrapper(*args, **kwargs):
        logging.debug(f"调用工具 {func.__name__} 参数: {args}, 关键字参数: {kwargs}")
        try:
            result = await func(*args, **kwargs)
            return result
        except Exception as e:
            logging.error(f"工具 {func.__name__} 调用失败: {e}")
            import traceback

            logging.error(traceback.format_exc())
            raise

    return wrapper


@click.group()
def cli():
    """Lanalyzer MCP 命令行工具"""
    pass


@cli.command()
@click.option("--debug", is_flag=True, help="启用调试模式")
@click.option("--host", default="127.0.0.1", help="主机地址")
@click.option("--port", default=8000, type=int, help="端口号")
def run(debug, host, port):
    """启动MCP服务器"""
    # 配置日志
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    click.echo(f"启动Lanalyzer MCP服务器 - 使用FastMCP v{__import__('fastmcp').__version__}")
    click.echo(f"服务器名称: Lanalyzer")
    click.echo(f"服务器版本: {__version__}")
    click.echo(f"服务器地址: {host}:{port}")

    # 创建FastMCP服务器实例
    server = create_mcp_server(debug=debug)

    # 使用兼容2.2.8版本的方式启动服务器
    click.echo(f"使用SSE传输启动FastMCP服务器")

    # 从帮助文档可以看出，FastMCP 2.2.8只支持'stdio'和'sse'两种传输方式
    server.run(
        transport="sse",  # 明确指定使用sse传输
        host=host,
        port=port,
    )


# 添加对mcp子命令的支持，保持原有功能
@cli.command()
@click.argument("mcp_command", nargs=-1)
@click.option("--debug", is_flag=True, help="启用调试模式")
def mcp(mcp_command, debug):
    """使用FastMCP命令行工具运行服务器（dev/run/install）"""
    import subprocess

    # 获取此文件的绝对路径
    script_path = os.path.abspath(__file__)

    # 构建FastMCP命令
    cmd = ["fastmcp"] + list(mcp_command)
    if not mcp_command or mcp_command[0] not in ["dev", "run", "install"]:
        # 如果没有提供有效的子命令，默认使用dev
        cmd = ["fastmcp", "dev"]

    # 添加模块路径
    cmd.append(script_path + ":mcp")

    # 明确指定传输方式为sse，避免默认使用http
    # 注意：FastMCP 2.2.8只支持stdio和sse传输
    if mcp_command and mcp_command[0] in ["dev", "run"]:
        cmd.append("--transport=sse")

    if debug:
        cmd.append("--with-debug")

    click.echo(f"执行命令: {' '.join(cmd)}")

    # 执行命令并将输出传递到当前终端
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        click.echo(f"命令执行失败: {e}")
        sys.exit(1)
    except FileNotFoundError:
        click.echo("错误: fastmcp 命令未找到。请确保已安装 FastMCP：pip install fastmcp")
        sys.exit(1)


def main():
    """主函数"""
    cli()


if __name__ == "__main__":
    main()
