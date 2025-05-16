"""
Enhanced AST visitor for taint analysis.
This is the main aggregation file that imports and combines all visitor components.
"""

from typing import Optional
import os
import ast  # 添加ast模块导入

from lanalyzer.logger import debug, warning, error

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

    def visit_ClassDef(self, node):
        """
        直接实现visit_ClassDef方法，确保类内方法调用被正确识别和处理
        """
        debug(f"[FORCE] 访问类定义: {node.name}")

        # 保存上一个类上下文
        previous_class = getattr(self, "current_class", None)
        self.current_class = node.name

        # 初始化类方法映射
        if not hasattr(self, "class_methods"):
            self.class_methods = {}

        # 创建当前类的方法映射
        if self.current_class not in self.class_methods:
            self.class_methods[self.current_class] = {
                "methods": set(),  # 类中所有方法名
                "calls": {},  # 方法间调用关系
            }

        # 处理类成员
        for item in node.body:
            item_type = type(item).__name__
            item_name = getattr(item, "name", None)
            debug(
                f"[FORCE] 类 {self.current_class} 成员: type={item_type}, name={item_name}"
            )

            # 设置父节点引用
            if not hasattr(item, "parent"):
                item.parent = node

            # 标记类方法
            if isinstance(item, ast.FunctionDef):
                debug(f"[FORCE] 找到类方法: {self.current_class}.{item.name}")
                self.class_methods[self.current_class]["methods"].add(item.name)

                # 重要：设置方法所属类信息
                if not hasattr(item, "class_name"):
                    item.class_name = self.current_class

                # 新增：检查方法体中对其他类方法的调用
                for stmt in item.body:
                    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                        call = stmt.value
                        if isinstance(call.func, ast.Attribute) and isinstance(
                            call.func.value, ast.Name
                        ):
                            if call.func.value.id == "self":
                                called_method = call.func.attr
                                if (
                                    called_method
                                    in self.class_methods[self.current_class]["methods"]
                                ):
                                    # 记录方法调用关系
                                    if (
                                        item.name
                                        not in self.class_methods[self.current_class][
                                            "calls"
                                        ]
                                    ):
                                        self.class_methods[self.current_class]["calls"][
                                            item.name
                                        ] = {}

                                    if (
                                        called_method
                                        not in self.class_methods[self.current_class][
                                            "calls"
                                        ][item.name]
                                    ):
                                        self.class_methods[self.current_class]["calls"][
                                            item.name
                                        ][called_method] = []

                                    line_no = getattr(stmt, "lineno", 0)
                                    self.class_methods[self.current_class]["calls"][
                                        item.name
                                    ][called_method].append(line_no)
                                    debug(
                                        f"[FORCE] 记录类内方法调用: {self.current_class}.{item.name} 调用 {self.current_class}.{called_method} 在第 {line_no} 行"
                                    )

                    # 递归检查更复杂的结构（如If语句内的调用）
                    for subnode in ast.walk(stmt):
                        if (
                            isinstance(subnode, ast.Call)
                            and isinstance(subnode.func, ast.Attribute)
                            and isinstance(subnode.func.value, ast.Name)
                        ):
                            if subnode.func.value.id == "self":
                                called_method = subnode.func.attr
                                if (
                                    called_method
                                    in self.class_methods[self.current_class]["methods"]
                                ):
                                    # 记录方法调用关系
                                    if (
                                        item.name
                                        not in self.class_methods[self.current_class][
                                            "calls"
                                        ]
                                    ):
                                        self.class_methods[self.current_class]["calls"][
                                            item.name
                                        ] = {}

                                    if (
                                        called_method
                                        not in self.class_methods[self.current_class][
                                            "calls"
                                        ][item.name]
                                    ):
                                        self.class_methods[self.current_class]["calls"][
                                            item.name
                                        ][called_method] = []

                                    line_no = getattr(subnode, "lineno", 0)
                                    self.class_methods[self.current_class]["calls"][
                                        item.name
                                    ][called_method].append(line_no)
                                    debug(
                                        f"[FORCE] 记录类内方法调用: {self.current_class}.{item.name} 调用 {self.current_class}.{called_method} 在第 {line_no} 行"
                                    )

        # 访问类成员
        self.generic_visit(node)

        # 输出类方法调用关系用于调试
        if self.debug and self.current_class in self.class_methods:
            methods = self.class_methods[self.current_class]["methods"]
            calls = self.class_methods[self.current_class]["calls"]
            debug(f"[FORCE] 类 {self.current_class} 的方法: {methods}")
            debug(f"[FORCE] 类 {self.current_class} 的方法调用关系: {calls}")

        # 恢复上一个类上下文
        self.current_class = previous_class

    def visit_Module(self, node):
        """直接实现visit_Module方法，确保所有顶级定义被正确处理"""
        debug(f"[FORCE] 开始分析模块: {getattr(self, 'file_path', None)}")

        # 初始化路径分析
        self.path_root = self.pathsensitive.PathNode(node)
        self.current_path = self.path_root

        # 为模块中的每个顶级定义设置父节点参考
        for child in node.body:
            if not hasattr(child, "parent"):
                child.parent = node

        # 继续处理模块内容
        self.generic_visit(node)

        # 输出分析结果统计
        if self.debug:
            debug(f"[FORCE] 模块分析完成，找到 {len(getattr(self, 'functions', {}))} 个函数")
            debug(f"[FORCE] 类方法关系: {getattr(self, 'class_methods', {})}")

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
                            f"Loaded {len(self.source_lines)} lines of source code from {file_path} into EnhancedTaintAnalysisVisitor"
                        )
                except Exception as e:
                    if self.debug:
                        error(
                            f"Failed to load source code in EnhancedTaintAnalysisVisitor: {str(e)}"
                        )
        if self.debug:
            debug(
                f"[FORCE] EnhancedTaintAnalysisVisitor initialized for file: {file_path}"
            )
            if hasattr(self, "source_lines") and self.source_lines:
                debug(
                    f"Successfully loaded source code lines: {len(self.source_lines)} lines"
                )
            else:
                warning("Warning: Failed to load source code lines")

    def visit(self, node):
        if self.debug:
            node_type = type(node).__name__
            node_name = getattr(node, "name", None)
            debug(
                f"[FORCE] EnhancedTaintAnalysisVisitor visiting node: {node_type}, name={node_name}"
            )
        return super().visit(node)
