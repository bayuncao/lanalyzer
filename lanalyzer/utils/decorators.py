"""
Decorator utilities for LAnaLyzer.

Provides useful decorator functions for enhancing functionality.
"""

import functools
import time
from typing import Any, Callable, Optional, TypeVar, cast

from lanalyzer.utils.logging import debug, error, info

F = TypeVar("F", bound=Callable[..., Any])


def timing_decorator(func: F) -> F:
    """
    Decorator to measure and log the execution time of a function.

    Args:
        func: The function to decorate

    Returns:
        Decorated function
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()

        function_name = func.__name__
        execution_time = end_time - start_time

        info(f"Function '{function_name}' executed in {execution_time:.4f} seconds")

        return result

    return cast(F, wrapper)


def deprecated(message: Optional[str] = None) -> Callable[[F], F]:
    """
    Decorator to mark functions as deprecated.

    Args:
        message: Optional message to include in the warning

    Returns:
        Decorator function
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            func_name = func.__name__
            warning_message = f"Function '{func_name}' is deprecated."
            if message:
                warning_message += f" {message}"
            info(warning_message)
            return func(*args, **kwargs)

        return cast(F, wrapper)

    return decorator


def debug_calls(func: F) -> F:
    """
    Decorator to log function calls with arguments and return values for debugging.

    Args:
        func: The function to decorate

    Returns:
        Decorated function
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        func_name = func.__name__
        args_repr = [repr(a) for a in args]
        kwargs_repr = [f"{k}={v!r}" for k, v in kwargs.items()]
        signature = ", ".join(args_repr + kwargs_repr)

        debug(f"Calling {func_name}({signature})")

        try:
            result = func(*args, **kwargs)
            debug(f"{func_name} returned {result!r}")
            return result
        except Exception as e:
            error(f"{func_name} raised {type(e).__name__}: {e}")
            raise

    return cast(F, wrapper)


def retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: tuple = (Exception,),
) -> Callable[[F], F]:
    """
    Decorator to retry function calls on failure.

    Args:
        max_attempts: Maximum number of attempts
        delay: Initial delay between attempts (in seconds)
        backoff: Backoff multiplier for delay
        exceptions: Tuple of exceptions to catch and retry

    Returns:
        Decorator function
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            mtries, mdelay = max_attempts, delay

            while mtries > 1:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    msg = f"{func.__name__} failed with {type(e).__name__}: {e}, retrying in {mdelay} seconds..."
                    info(msg)

                    time.sleep(mdelay)
                    mtries -= 1
                    mdelay *= backoff

            # Last attempt
            return func(*args, **kwargs)

        return cast(F, wrapper)

    return decorator
