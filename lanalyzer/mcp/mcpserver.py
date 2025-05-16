#!/usr/bin/env python
"""
MCP server command-line entry point, implemented using FastMCP.
Provides Model Context Protocol (MCP) functionality for lanalyzer.
"""

import os
import sys
import logging
import click
from typing import Optional, Dict, Any

try:
    # Import FastMCP core components
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


def create_mcp_server(debug: bool = False) -> FastMCP:
    """
    创建FastMCP服务器实例。

    这是MCP模块的核心工厂函数，用于创建和配置FastMCP服务器实例。

    Args:
        debug: 是否启用调试模式。

    Returns:
        FastMCP: 服务器实例。
    """
    # 配置日志级别
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # 检查FastMCP版本
    try:
        fastmcp_version = __import__("fastmcp").__version__
        logging.info(f"FastMCP版本: {fastmcp_version}")
    except (ImportError, AttributeError):
        logging.warning("无法确定FastMCP版本")
        fastmcp_version = "unknown"

    # 创建FastMCP实例 - 参数为兼容版本2.2.8移除了一些选项
    mcp = FastMCP(
        "Lanalyzer",
        title="Lanalyzer - Python Taint Analysis Tool",
        description="MCP server for Lanalyzer, providing taint analysis for Python code to detect security vulnerabilities.",
        version=__version__,
        debug=debug,
    )

    # 创建处理器实例
    handler = LanalyzerMCPHandler(debug=debug)

    # 在调试模式下启用请求日志记录
    if debug:
        try:

            @mcp.middleware
            async def log_requests(request, call_next):
                """记录请求和响应的中间件"""
                logging.debug(f"收到请求: {request.method} {request.url}")
                try:
                    if request.method == "POST":
                        body = await request.json()
                        logging.debug(f"请求体: {body}")
                except Exception as e:
                    logging.debug(f"无法解析请求体: {e}")

                response = await call_next(request)
                return response

        except AttributeError:
            # 如果FastMCP不支持middleware，记录一条警告日志
            logging.warning("当前FastMCP版本不支持middleware功能，日志记录功能将被禁用")

    @mcp.tool()
    async def analyze_code(
        code: str, file_path: str, config_path: str, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        分析提供的Python代码以检测安全漏洞。

        Args:
            code: 要分析的Python代码。
            file_path: 代码的文件路径（用于报告）。
            config_path: 配置文件路径（必需）。
            ctx: MCP上下文。

        Returns:
            分析结果，包括检测到的漏洞信息。
        """
        # 记录原始参数以帮助调试
        logging.debug(
            f"analyze_code原始参数: code=<已省略>, file_path={file_path}, config_path={config_path}"
        )

        # 处理可能的嵌套参数结构
        actual_file_path = file_path
        actual_config_path = config_path
        actual_code = code

        # 嵌套参数处理
        if isinstance(config_path, dict) and not isinstance(code, str):
            logging.warning(f"检测到嵌套参数结构: {config_path}")

            # 尝试从嵌套结构中提取参数
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

            # 如果找不到有效的代码
            if not isinstance(actual_code, str):
                error_msg = "无法从请求中提取有效的code参数"
                if ctx:
                    await ctx.error(error_msg)
                return {"success": False, "errors": [error_msg]}

        if ctx:
            await ctx.info(f"开始代码分析, 文件路径: {actual_file_path}")
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
            await ctx.warning(f"检测到{len(result.vulnerabilities)}个潜在漏洞")

        return result.model_dump()

    @mcp.tool()
    async def analyze_file(
        file_path: str, config_path: str, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        分析指定文件路径的Python代码。

        Args:
            file_path: 要分析的Python文件的路径。
            config_path: 配置文件路径（必需）。
            ctx: MCP上下文。

        Returns:
            分析结果，包括检测到的漏洞信息。
        """
        # 记录原始参数以帮助调试
        logging.debug(
            f"analyze_file原始参数: file_path={file_path}, config_path={config_path}"
        )

        # 处理嵌套参数情况
        # 在客户端错误地发送嵌套参数结构时纠正
        actual_file_path = file_path
        actual_config_path = config_path
        is_nested_params = False

        if isinstance(config_path, dict):
            logging.warning(f"嵌套参数情况 (config_path是字典): {config_path}")
            is_nested_params = True

            # 尝试从嵌套结构中提取参数
            if "file_path" in config_path and isinstance(config_path["file_path"], str):
                actual_file_path = config_path["file_path"]
                logging.warning(f"从嵌套结构中提取file_path: {actual_file_path}")

            if "config_path" in config_path and isinstance(
                config_path["config_path"], str
            ):
                actual_config_path = config_path["config_path"]
                logging.warning(f"从嵌套结构中提取config_path: {actual_config_path}")

        # 如果file_path也是一个字典
        if isinstance(file_path, dict) and not is_nested_params:
            logging.warning(f"嵌套参数情况 (file_path是字典): {file_path}")

            # 尝试从嵌套结构中提取参数
            if "file_path" in file_path and isinstance(file_path["file_path"], str):
                actual_file_path = file_path["file_path"]
                logging.warning(f"从嵌套结构中提取file_path: {actual_file_path}")

            if "config_path" in file_path and isinstance(file_path["config_path"], str):
                actual_config_path = file_path["config_path"]
                logging.warning(f"从嵌套结构中提取config_path: {actual_config_path}")

        if ctx:
            await ctx.info(f"开始文件分析: {actual_file_path}")
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

        # 创建请求对象并处理
        request = FileAnalysisRequest(
            file_path=actual_file_path, config_path=actual_config_path
        )
        result = await handler.handle_file_analysis_request(request)

        if ctx and result.vulnerabilities:
            await ctx.warning(f"检测到{len(result.vulnerabilities)}个潜在漏洞")

        return result.model_dump()

    @mcp.tool()
    async def get_config(
        config_path: Optional[str] = None, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        获取配置内容。

        Args:
            config_path: 配置文件的路径。
            ctx: MCP上下文。

        Returns:
            配置数据。
        """
        if ctx:
            config_desc = config_path if config_path else "默认配置"
            await ctx.info(f"获取配置: {config_desc}")

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
        验证配置内容。

        Args:
            config_data: 要验证的配置数据。
            config_path: 可选的配置文件路径（如果提供，将从文件中读取）。
            ctx: MCP上下文。

        Returns:
            验证结果。
        """
        if ctx:
            await ctx.info("验证配置...")

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
        创建新的配置文件。

        Args:
            config_data: 配置数据。
            config_path: 可选的输出文件路径。
            ctx: MCP上下文。

        Returns:
            创建操作的结果。
        """
        if ctx:
            path_info = f", 保存至: {config_path}" if config_path else ""
            await ctx.info(f"创建配置{path_info}")

        request = ConfigurationRequest(
            operation="create", config_path=config_path, config_data=config_data
        )
        result = await handler.handle_configuration_request(request)

        if ctx and result.success:
            await ctx.info("配置创建成功")

        return result.model_dump()

    return mcp


# 调试工具函数装饰器，在调试模式下使用
def debug_tool_args(func):
    """记录工具函数参数用于调试"""

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
    """Lanalyzer MCP命令行工具"""
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

    # 以兼容版本2.2.8的方式启动服务器
    click.echo(f"使用SSE传输启动FastMCP服务器")

    # 根据帮助文档，FastMCP 2.2.8只支持'stdio'和'sse'传输方法
    server.run(
        transport="sse",  # 明确指定使用sse传输
        host=host,
        port=port,
    )


@cli.command(name="mcp")
@click.argument("command_args", nargs=-1)
@click.option("--debug", is_flag=True, help="启用调试模式")
def mcpcmd(command_args, debug):
    """使用FastMCP命令行工具运行服务器(dev/run/install)"""
    import subprocess

    # 获取此文件的绝对路径
    script_path = os.path.abspath(__file__)

    # 构建FastMCP命令
    cmd = ["fastmcp"] + list(command_args)
    if not command_args or command_args[0] not in ["dev", "run", "install"]:
        # 如果没有提供有效的子命令，默认为dev
        cmd = ["fastmcp", "dev"]

    # 添加模块路径 - 我们将创建一个临时服务器实例
    temp_var_name = "server"
    cmd.append(f"{script_path}:{temp_var_name}")

    # 明确指定传输为sse以避免默认http
    # 注意：FastMCP 2.2.8只支持stdio和sse传输
    if command_args and command_args[0] in ["dev", "run"]:
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
        click.echo("错误: 找不到fastmcp命令。请确保已安装FastMCP: pip install fastmcp")
        sys.exit(1)


# 为FastMCP命令行提供临时服务器变量
server = create_mcp_server()


if __name__ == "__main__":
    cli()
