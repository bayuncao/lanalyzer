"""
Logger decorator module - provides decorators for automatic logging functionality.
"""

import functools
import inspect
import os
from typing import Any, Callable, TypeVar, cast

from lanalyzer.logger.core import critical, debug, error, info, warning

# Type variable for various types of functions
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
            # Get function name and call location
            module = inspect.getmodule(func)
            module_name = module.__name__ if module else "unknown_module"
            func_name = f"{module_name}.{func.__name__}"

            # Log function start execution
            log_func(f"Starting execution of {func_name}")

            try:
                result = func(*args, **kwargs)
                # Log function execution success
                log_func(f"Finished execution of {func_name}")
                return result
            except Exception as e:
                # Log function execution exception
                error(
                    f"Error during execution of {func_name}: {type(e).__name__}: {str(e)}"
                )
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
        # Try to find the file path from the arguments
        file_path = None
        if (
            args and isinstance(args[0], str) and os.path.exists(args[0])
        ):  # Check first positional arg
            file_path = args[0]
        # If not found in positional arguments, try checking keyword arguments
        elif (
            "file_path" in kwargs
            and isinstance(kwargs["file_path"], str)
            and os.path.exists(kwargs["file_path"])
        ):
            file_path = kwargs["file_path"]
        elif (
            "target_path" in kwargs
            and isinstance(kwargs["target_path"], str)
            and os.path.exists(kwargs["target_path"])
        ):  # Common alternative
            file_path = kwargs["target_path"]

        if file_path:
            info(f"🔍 Starting analysis for: {file_path}")

        try:
            result = func(*args, **kwargs)

            if file_path:
                info(f"✅ Finished analysis for: {file_path}")

            return result
        except Exception as e:
            if file_path:
                error(
                    f"❌ Error during analysis of {file_path}: {type(e).__name__}: {str(e)}"
                )
            else:
                error(
                    f"❌ Error during analysis (file path unknown): {type(e).__name__}: {str(e)}"
                )
            raise

    return cast(F, wrapper)


def log_result(func: F) -> F:
    """
    Decorator for logging the return value of a function.
    Suitable for functions that return simple types or collections.

    Returns:
        Decorated function
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        result = func(*args, **kwargs)
        func_name = func.__name__

        # Check result and log
        if isinstance(result, (list, set, tuple)):
            info(f"{func_name} returned {len(result)} item(s)")
        elif isinstance(result, dict):
            info(
                f"{func_name} returned a dictionary with {len(result)} key-value pair(s)"
            )
        elif result is not None:
            # For other types, log the result if it's not too large or complex
            # This is a simple check; more sophisticated checks might be needed for large objects
            result_str = str(result)
            if len(result_str) < 100:  # Avoid logging overly large strings
                debug(f"{func_name} returned: {result_str}")
            else:
                debug(f"{func_name} returned a result of type {type(result).__name__}")
        else:
            debug(f"{func_name} returned None")

        return result

    return cast(F, wrapper)


def conditional_log(
    condition_arg: str, log_message: str, level: str = "info"
) -> Callable[[F], F]:
    """
    Conditional logging decorator based on an argument's value.

    Args:
        condition_arg: The name of the argument to check.
        log_message: Log message template, can use '{param_value}' to reference the argument's value.
        level: Log level, options: "debug", "info", "warning", "error", "critical".

    Returns:
        Decorator function.
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
            # Get the value of the parameter to be checked
            param_value_to_check = None

            # Check parameter signature to determine parameter position
            sig = inspect.signature(func)
            param_names = list(sig.parameters.keys())

            if condition_arg in kwargs:
                param_value_to_check = kwargs[condition_arg]
            elif condition_arg in param_names:
                try:
                    pos = param_names.index(condition_arg)
                    if pos < len(args):
                        param_value_to_check = args[pos]
                    # If not in args, it might be a kwarg not yet processed or a default not overridden
                except ValueError:
                    pass  # condition_arg not found in positional mapping

            # If the conditional parameter has a value (evaluates to True in a boolean context)
            if param_value_to_check:
                # Format message, replace parameter reference
                try:
                    formatted_message = log_message.format(
                        param_value=param_value_to_check
                    )
                except KeyError:  # Handle if log_message has other placeholders
                    formatted_message = log_message
                log_func(formatted_message)

            # Execute original function
            return func(*args, **kwargs)

        return cast(F, wrapper)

    return decorator


def log_vulnerabilities(func: F) -> F:
    """
    Decorator specifically for logging vulnerability findings.

    Assumes the decorated function returns a list of vulnerabilities (or similar iterable).

    Returns:
        Decorated function
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        result = func(*args, **kwargs)
        func_name = func.__name__

        # Check if the result is a list (common for vulnerabilities)
        if isinstance(result, list):
            vulnerability_count = len(result)
            if vulnerability_count > 0:
                info(
                    f"{func_name} found {vulnerability_count} potential vulnerabilit{'y' if vulnerability_count == 1 else 'ies'}."
                )
            else:
                info(f"{func_name} found no vulnerabilities.")
        # Add handling for other iterable types if necessary, or a more generic check
        elif hasattr(result, "__len__"):  # Generic check for sized iterables
            try:
                count = len(result)  # type: ignore
                if count > 0:
                    info(
                        f"{func_name} identified {count} item(s) (assumed vulnerabilities)."
                    )
                else:
                    info(f"{func_name} identified no items (assumed vulnerabilities).")
            except TypeError:
                # Not all sized iterables are necessarily vulnerability lists
                debug(
                    f"{func_name} returned a result of type {type(result).__name__}, not logging as vulnerabilities."
                )
        else:
            debug(
                f"{func_name} did not return a list or known iterable for vulnerability logging."
            )

        return result

    return cast(F, wrapper)
