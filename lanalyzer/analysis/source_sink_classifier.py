"""source_sink_classifier.py
提取源/汇（sink）分类判断逻辑，供 AST 访客等使用。
"""
from __future__ import annotations

import re
from typing import Optional

from lanalyzer.logger import get_logger

logger = get_logger("lanalyzer.analysis.source_sink_classifier")


class SourceSinkClassifier:
    """根据配置判断函数是否为 taint 源或汇。"""

    def __init__(self, visitor) -> None:
        # 访客需暴露 .sources, .sinks, .debug, 以及 import 映射集合
        self.visitor = visitor
        # 用于新架构的配置存储
        self._sources = []
        self._sinks = []

    def configure(self, sources, sinks):
        """配置源和汇的定义（新架构使用）"""
        self._sources = sources or []
        self._sinks = sinks or []
        # 同时更新 visitor 的属性以保持兼容性
        if hasattr(self.visitor, 'sources'):
            self.visitor.sources = self._sources
        if hasattr(self.visitor, 'sinks'):
            self.visitor.sinks = self._sinks

    @property
    def sources(self):
        """获取源配置"""
        if hasattr(self.visitor, 'sources') and self.visitor.sources:
            return self.visitor.sources
        return self._sources

    @property
    def sinks(self):
        """获取汇配置"""
        if hasattr(self.visitor, 'sinks') and self.visitor.sinks:
            return self.visitor.sinks
        return self._sinks

    # --------------------------- public helpers ---------------------------
    def is_source(self, func_name: str, full_name: Optional[str] = None) -> bool:
        return self._match_patterns(self.sources, func_name, full_name)

    def source_type(self, func_name: str, full_name: Optional[str] = None) -> str:
        return self._get_type(self.sources, func_name, full_name)

    def is_sink(self, func_name: str, full_name: Optional[str] = None) -> bool:
        return self._match_patterns(self.sinks, func_name, full_name)

    def sink_type(self, func_name: str, full_name: Optional[str] = None) -> str:
        return self._get_type(self.sinks, func_name, full_name)

    def sink_vulnerability_type(self, sink_type: str) -> str:
        for sink in self.sinks:
            if sink.get("name") == sink_type:
                return sink.get("vulnerability_type", "vulnerability")
        return "vulnerability"

    # --------------------------- internal utils ---------------------------
    @staticmethod
    def _match_patterns(config_list, func_name: str, full_name: Optional[str]) -> bool:
        if not isinstance(func_name, str):
            return False
        if full_name is not None and not isinstance(full_name, str):
            full_name = None
        for item in config_list:
            for pattern in item.get("patterns", []):
                # Normalize pattern by removing trailing parentheses for function calls
                normalized_pattern = pattern.rstrip("(")

                # Direct match with normalized pattern
                if normalized_pattern == func_name or (full_name and normalized_pattern == full_name):
                    return True

                # Check if pattern is contained in full_name
                if pattern in (full_name or ""):
                    return True

                # Check if normalized pattern is contained in full_name
                if normalized_pattern in (full_name or ""):
                    return True

                # Wildcard matching
                if "*" in pattern:
                    regex_pattern = pattern.replace(".", "\\.").replace("*", ".*")
                    if re.match(regex_pattern, func_name) or (
                        full_name and re.match(regex_pattern, full_name)
                    ):
                        return True
        return False

    @staticmethod
    def _get_type(config_list, func_name: str, full_name: Optional[str]) -> str:
        if full_name is not None and not isinstance(full_name, str):
            full_name = None
        for item in config_list:
            for pattern in item.get("patterns", []):
                # Normalize pattern by removing trailing parentheses for function calls
                normalized_pattern = pattern.rstrip("(")

                # Direct match with normalized pattern
                if normalized_pattern == func_name or (full_name and normalized_pattern == full_name):
                    return item.get("name", "Unknown")

                # Check if pattern is contained in full_name
                if pattern in (full_name or ""):
                    return item.get("name", "Unknown")

                # Check if normalized pattern is contained in full_name
                if normalized_pattern in (full_name or ""):
                    return item.get("name", "Unknown")

                # Wildcard matching
                if "*" in pattern:
                    regex_pattern = pattern.replace(".", "\\.").replace("*", ".*")
                    if re.match(regex_pattern, func_name) or (
                        full_name and re.match(regex_pattern, full_name)
                    ):
                        return item.get("name", "Unknown")
        return "Unknown"