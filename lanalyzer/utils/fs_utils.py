"""
文件系统实用工具模块，为 LanaLyzer 提供文件和路径操作。

本模块提供污点分析引擎使用的常见文件和路径操作。
"""

import os
from pathlib import Path
from typing import List, Optional


def is_python_file(file_path: str) -> bool:
    """
    检查文件是否为 Python 文件。

    Args:
        file_path: 文件路径

    Returns:
        如果文件扩展名为 .py 则返回 True，否则返回 False
    """
    return file_path.lower().endswith(".py")


def get_python_files_in_directory(
    directory: str, recursive: bool = True, exclude_dirs: List[str] = None
) -> List[str]:
    """
    获取目录中的所有 Python 文件。

    Args:
        directory: 用于搜索 Python 文件的目录
        recursive: 是否递归搜索子目录
        exclude_dirs: 要排除的目录名称列表（例如 ["venv", "__pycache__"]）

    Returns:
        Python 文件路径列表
    """
    exclude_dirs = exclude_dirs or ["__pycache__", "venv", ".git", ".github"]
    python_files = []

    # 处理输入是文件而非目录的情况
    if os.path.isfile(directory):
        if is_python_file(directory):
            return [directory]
        return []

    if recursive:
        for root, dirs, files in os.walk(directory):
            # 跳过被排除的目录
            dirs[:] = [d for d in dirs if d not in exclude_dirs]

            for file in files:
                if is_python_file(file):
                    python_files.append(os.path.join(root, file))
    else:
        # 非递归搜索
        for item in os.listdir(directory):
            item_path = os.path.join(directory, item)
            if os.path.isfile(item_path) and is_python_file(item_path):
                python_files.append(item_path)

    return python_files


def ensure_directory_exists(directory_path: str) -> None:
    """
    确保目录存在，如有必要则创建目录。

    Args:
        directory_path: 目录路径
    """
    Path(directory_path).mkdir(parents=True, exist_ok=True)


def get_relative_path(base_path: str, full_path: str) -> str:
    """
    将绝对路径转换为相对于基础路径的路径。

    Args:
        base_path: 基础目录路径
        full_path: 要转换为相对路径的完整路径

    Returns:
        相对于基础路径的路径
    """
    try:
        return os.path.relpath(full_path, base_path)
    except ValueError:
        # 处理路径在不同驱动器上的情况（Windows）
        return full_path


def get_absolute_path(path: str, relative_to: Optional[str] = None) -> str:
    """
    将相对路径转换为绝对路径。

    Args:
        path: 要转换为绝对路径的路径
        relative_to: 相对路径的基础目录（默认值：当前工作目录）

    Returns:
        绝对路径
    """
    if os.path.isabs(path):
        return path

    base_dir = relative_to or os.getcwd()
    return os.path.normpath(os.path.join(base_dir, path))
