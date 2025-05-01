"""
Logger decorator module - provides decorators for automatic logging functionality.
"""

import functools
import inspect
import os
from typing import Any, Callable, TypeVar, cast

from lanalyzer.logger.core import debug, info, warning, error, critical

# 可用于各种类型的函数的类型变量
F = TypeVar("F", bound=Callable[..., Any])


def log_function(level: str = "info") -> Callable[[F], F]:
    """
    Function execution logger decorator - logs the start and end of a function.

    Args:
        level: Log level, options: "debug", "info", "warning", "error", "critical"

    Returns:
        Decorator function
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
            log_func(f"Start executing {func_name}")

            try:
                result = func(*args, **kwargs)
                # 记录函数执行成功
                log_func(f"Finished executing {func_name}")
                return result
            except Exception as e:
                # 记录函数执行异常
                error(f"{func_name} execution error: {type(e).__name__}: {str(e)}")
                raise

        return cast(F, wrapper)

    return decorator


def log_analysis_file(func: F) -> F:
    """
    Decorator for logging file analysis, specifically for functions handling file analysis.

    This decorator assumes the decorated function has at least one argument as the file path.

    Returns:
        Decorated function
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
            info(f"🔍 Start analyzing file: {file_path}")

        try:
            result = func(*args, **kwargs)

            if file_path:
                info(f"✅ Finished analyzing file: {file_path}")

            return result
        except Exception as e:
            if file_path:
                error(
                    f"❌ File analysis error {file_path}: {type(e).__name__}: {str(e)}"
                )
            raise

    return cast(F, wrapper)


def log_result(func: F) -> F:
    """
    Decorator for logging the return value of a function.
    Suitable for functions that return simple types.

    Returns:
        Decorated function
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        result = func(*args, **kwargs)

        # 检查结果并记录
        if isinstance(result, (list, set, tuple)) and len(result) > 0:
            info(f"{func.__name__} returned {len(result)} items")
        elif isinstance(result, dict) and len(result) > 0:
            info(f"{func.__name__} returned {len(result)} key-value pairs")
        elif result is not None:
            debug(f"{func.__name__} return value: {result}")

        return result

    return cast(F, wrapper)


def conditional_log(
    condition_arg: str, log_message: str, level: str = "info"
) -> Callable[[F], F]:
    """
    Conditional logging decorator based on argument value.

    Args:
        condition_arg: The argument name to check
        log_message: Log message template, can use '{param}' to reference argument value
        level: Log level, options: "debug", "info", "warning", "error", "critical"

    Returns:
        Decorator function
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
    Decorator specifically for logging vulnerability findings.

    Assumes the decorated function returns a list of vulnerabilities.

    Returns:
        Decorated function
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        result = func(*args, **kwargs)

        # 检查结果是否为漏洞列表
        if isinstance(result, list):
            vulnerability_count = len(result)
            if vulnerability_count > 0:
                info(f"Found {vulnerability_count} potential vulnerabilities")
            else:
                info("No vulnerabilities found")

        return result

    return cast(F, wrapper)
