"""
Enhanced AST visitor for taint analysis.
This is the main aggregation file that imports and combines all visitor components.
"""

from typing import Optional
import os

from lanalyzer.logger import debug, info, warning, error

from .visitor_base import EnhancedTaintVisitor
from .visitor_function import FunctionVisitorMixin
from .visitor_datastructure import DataStructureVisitorMixin
from .visitor_control import ControlFlowVisitorMixin

import importlib

for module_name in ["callgraph", "datastructures", "defuse", "pathsensitive"]:
    globals()[module_name] = importlib.import_module(
        f".{module_name}", package="lanalyzer.analysis"
    )


class EnhancedTaintAnalysisVisitor(
    EnhancedTaintVisitor,
    FunctionVisitorMixin,
    DataStructureVisitorMixin,
    ControlFlowVisitorMixin,
):
    """
    This class combines all the visitor mixins to create a complete taint analysis visitor.

    - EnhancedTaintVisitor: Base visitor with core functionality
    - FunctionVisitorMixin: Function definition and call tracking
    - DataStructureVisitorMixin: Complex data structure tracking
    - ControlFlowVisitorMixin: Control flow analysis
    """

    def __init__(
        self,
        parent_map=None,
        debug_mode: bool = False,
        verbose: bool = False,
        file_path: Optional[str] = None,
    ):
        """Initialize the complete taint analysis visitor."""
        self.callgraph = globals()["callgraph"]
        self.datastructures = globals()["datastructures"]
        self.defuse = globals()["defuse"]
        self.pathsensitive = globals()["pathsensitive"]
        super().__init__(parent_map, debug_mode, verbose, file_path)
        if not hasattr(self, "source_lines") or not self.source_lines:
            if file_path and os.path.exists(file_path):
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        self.source_lines = f.readlines()
                    if self.debug:
                        debug(
                            f"从 {file_path} 加载了 {len(self.source_lines)} 行源代码到 EnhancedTaintAnalysisVisitor"
                        )
                except Exception as e:
                    if self.debug:
                        error(f"在 EnhancedTaintAnalysisVisitor 中加载源代码失败: {str(e)}")
        if self.debug:
            debug(f"正在初始化完整污点分析访问器，文件: {file_path}")
            if hasattr(self, "source_lines") and self.source_lines:
                debug(f"成功加载源代码行: {len(self.source_lines)} 行")
            else:
                warning("警告: 加载源代码行失败")
