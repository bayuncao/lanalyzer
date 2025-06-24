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

    # --------------------------- public helpers ---------------------------
    def is_source(self, func_name: str, full_name: Optional[str] = None) -> bool:
        return self._match_patterns(self.visitor.sources, func_name, full_name)

    def source_type(self, func_name: str, full_name: Optional[str] = None) -> str:
        return self._get_type(self.visitor.sources, func_name, full_name)

    def is_sink(self, func_name: str, full_name: Optional[str] = None) -> bool:
        return self._match_patterns(self.visitor.sinks, func_name, full_name)

    def sink_type(self, func_name: str, full_name: Optional[str] = None) -> str:
        return self._get_type(self.visitor.sinks, func_name, full_name)

    def sink_vulnerability_type(self, sink_type: str) -> str:
        for sink in self.visitor.sinks:
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
                if pattern == func_name or (full_name and pattern == full_name):
                    return True
                if pattern in (full_name or ""):
                    return True
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
                if pattern == func_name or (full_name and pattern in full_name):
                    return item.get("name", "Unknown")
                if "*" in pattern:
                    regex_pattern = pattern.replace(".", "\\.").replace("*", ".*")
                    if re.match(regex_pattern, func_name) or (
                        full_name and re.match(regex_pattern, full_name)
                    ):
                        return item.get("name", "Unknown")
        return "Unknown" 