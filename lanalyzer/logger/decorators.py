"""
日志装饰器模块 - 提供自动添加日志功能的装饰器。
"""

import functools
import inspect
import os
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar, Union, cast

from lanalyzer.logger.core import debug, info, warning, error, critical

# 可用于各种类型的函数的类型变量
F = TypeVar("F", bound=Callable[..., Any])


def log_function(level: str = "info") -> Callable[[F], F]:
    """
    函数执行日志装饰器 - 记录函数的开始和结束。

    参数:
        level: 日志级别，可选值: "debug", "info", "warning", "error", "critical"

    返回:
        装饰器函数
    """
    log_funcs = {
        "debug": debug,
        "info": info,
        "warning": warning,
        "error": error,
        "critical": critical,
    }

    log_func = log_funcs.get(level, info)

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # 获取函数名和调用位置
            module = inspect.getmodule(func)
            module_name = module.__name__ if module else "unknown"
            func_name = f"{module_name}.{func.__name__}"

            # 记录函数开始执行
            log_func(f"开始执行 {func_name}")

            try:
                result = func(*args, **kwargs)
                # 记录函数执行成功
                log_func(f"完成执行 {func_name}")
                return result
            except Exception as e:
                # 记录函数执行异常
                error(f"{func_name} 执行出错: {type(e).__name__}: {str(e)}")
                raise

        return cast(F, wrapper)

    return decorator


def log_analysis_file(func: F) -> F:
    """
    用于记录文件分析的装饰器，专门针对处理文件分析的函数。

    此装饰器假设被装饰的函数至少有一个参数是文件路径。

    返回:
        装饰后的函数
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        # 尝试从参数中找到文件路径
        file_path = None
        if args and isinstance(args[0], str) and os.path.exists(args[0]):
            file_path = args[0]

        # 如果在位置参数中找不到，尝试查看关键字参数
        if not file_path and "file_path" in kwargs:
            if isinstance(kwargs["file_path"], str) and os.path.exists(
                kwargs["file_path"]
            ):
                file_path = kwargs["file_path"]

        if file_path:
            info(f"🔍 开始分析文件: {file_path}")

        try:
            result = func(*args, **kwargs)

            if file_path:
                info(f"✅ 完成分析文件: {file_path}")

            return result
        except Exception as e:
            if file_path:
                error(f"❌ 分析文件出错 {file_path}: {type(e).__name__}: {str(e)}")
            raise

    return cast(F, wrapper)


def log_result(func: F) -> F:
    """
    记录函数返回结果的装饰器。
    适用于返回值是简单类型的函数。

    返回:
        装饰后的函数
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        result = func(*args, **kwargs)

        # 检查结果并记录
        if isinstance(result, (list, set, tuple)) and len(result) > 0:
            info(f"{func.__name__} 返回了 {len(result)} 个项目")
        elif isinstance(result, dict) and len(result) > 0:
            info(f"{func.__name__} 返回了 {len(result)} 个键值对")
        elif result is not None:
            debug(f"{func.__name__} 返回结果: {result}")

        return result

    return cast(F, wrapper)


def conditional_log(
    condition_arg: str, log_message: str, level: str = "info"
) -> Callable[[F], F]:
    """
    基于条件参数值的日志装饰器。

    参数:
        condition_arg: 要检查的参数名称
        log_message: 日志消息模板，可以使用 '{param}' 格式引用参数值
        level: 日志级别，可选值: "debug", "info", "warning", "error", "critical"

    返回:
        装饰器函数
    """
    log_funcs = {
        "debug": debug,
        "info": info,
        "warning": warning,
        "error": error,
        "critical": critical,
    }

    log_func = log_funcs.get(level, info)

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # 获取被检查的参数值
            param_value = None

            # 检查参数签名以确定参数位置
            sig = inspect.signature(func)
            param_names = list(sig.parameters)

            # 检查位置参数
            if condition_arg in param_names:
                pos = param_names.index(condition_arg)
                if pos < len(args):
                    param_value = args[pos]
                elif condition_arg in kwargs:
                    param_value = kwargs[condition_arg]

            # 如果条件参数有值，记录日志
            if param_value:
                # 格式化消息，替换参数引用
                formatted_message = log_message.format(param=param_value)
                log_func(formatted_message)

            # 执行原始函数
            return func(*args, **kwargs)

        return cast(F, wrapper)

    return decorator


def log_vulnerabilities(func: F) -> F:
    """
    专门用于记录漏洞查找结果的装饰器。

    假设被装饰的函数返回漏洞列表。

    返回:
        装饰后的函数
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        result = func(*args, **kwargs)

        # 检查结果是否为漏洞列表
        if isinstance(result, list):
            vulnerability_count = len(result)
            if vulnerability_count > 0:
                info(f"发现 {vulnerability_count} 个潜在漏洞")
            else:
                info("未发现漏洞")

        return result

    return cast(F, wrapper)
