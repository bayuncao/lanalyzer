"""
Enhanced AST visitor for taint analysis - Base Visitor.
"""

import ast
import os
from typing import Callable, Dict, Optional, Tuple

from lanalyzer.analysis.ast_parser import TaintVisitor

from .pathsensitive import PathNode


class EnhancedTaintVisitor(TaintVisitor):
    """
    Enhanced taint visitor with additional features:
    1. Cross-function call taint tracking
    2. Complex data structure taint propagation
    3. Definition-use chain analysis
    4. Path-sensitive analysis
    """

    def __init__(
        self,
        parent_map=None,
        debug: bool = False,
        verbose: bool = False,
        file_path: Optional[str] = None,
    ):
        """
        Initialize the enhanced taint visitor.

        Args:
            parent_map: Dictionary mapping AST nodes to their parents
            debug: Whether to enable debug output
            verbose: Whether to enable verbose output
            file_path: Path to the file being analyzed
        """
        super().__init__(parent_map, debug, verbose)
        self.file_path = file_path
        self.source_lines = None  # Will store source code lines

        # If file path is provided, try to load the source code
        if file_path and os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    self.source_lines = f.readlines()
                if self.debug:
                    print(
                        f"Loaded {len(self.source_lines)} lines of source code from {file_path}"
                    )
            except Exception as e:
                if self.debug:
                    print(f"Failed to load source code: {str(e)}")

        # For compatibility with the updated TaintVisitor, which uses "tainted"
        # instead of "variable_taint". This makes variable_taint an alias to tainted.
        self.variable_taint = self.tainted if hasattr(self, "tainted") else {}

        # Initialize sources and sinks from the tracker
        self.sources = []
        self.sinks = []

        # 存储源代码位置信息
        self.source_statements = {}  # 跟踪每个污点源的具体语句

        # Call graph related
        self.functions = {}  # name -> CallGraphNode
        self.current_function = None  # Current function being analyzed
        self.call_locations = []  # Stack of call locations

        # Complex data structures
        self.data_structures = {}  # name -> DataStructureNode

        # Definition-use chains
        self.def_use_chains = {}  # name -> DefUseChain

        # Path-sensitive analysis
        self.path_root = None  # Root of the path tree
        self.current_path = None  # Current path being analyzed
        self.path_constraints = []  # Stack of path constraints

        # Track taint propagation path
        self.taint_propagation_paths = {}  # var_name -> list of propagation steps

        # Function return taint tracking
        self.function_returns_tainted = {}  # function_name -> bool

        # Cross-module imports
        self.module_imports = {}  # imported_name -> (module, original_name)

        # Enhanced file handle tracking
        self.file_handle_operations = {}  # handle_name -> list of operations

        # Improved taint tracking for complex operations
        self.operation_taint_rules = self._initialize_operation_taint_rules()

        # 增强特定数据流跟踪
        self.data_flow_targets = {}  # 用于跟踪特定的数据流模式
        self.var_assignments = {}  # 用于跟踪变量的赋值来源
        self.var_uses = {}  # 用于跟踪变量的使用位置

        # Increased initialization debug info
        if self.debug:
            print(
                f"Creating EnhancedTaintVisitor instance for analyzing file: {self.file_path}"
            )

    def _initialize_operation_taint_rules(self) -> Dict[str, Callable]:
        """Initialize rules for how taint propagates through different operations."""
        rules = {}

        # String operations that propagate taint
        string_propagating_methods = [
            "strip",
            "lstrip",
            "rstrip",
            "upper",
            "lower",
            "title",
            "capitalize",
            "swapcase",
            "replace",
            "format",
            "join",
            "split",
            "rsplit",
            "splitlines",
            "partition",
            "rpartition",
        ]

        for method in string_propagating_methods:
            rules[f"str.{method}"] = lambda node, source_info: source_info

        # List/dict operations that propagate taint
        container_propagating_methods = ["copy", "items", "keys", "values"]
        for method in container_propagating_methods:
            rules[f"dict.{method}"] = lambda node, source_info: source_info
            rules[f"list.{method}"] = lambda node, source_info: source_info

        # Numpy/tensor operations that propagate taint
        data_propagating_methods = [
            "numpy",
            "tobytes",
            "tensor",
            "array",
            "astype",
            "decode",
            "encode",
        ]
        for method in data_propagating_methods:
            rules[method] = lambda node, source_info: source_info

        return rules

    def visit_Module(self, node: ast.Module) -> None:
        """Visit a module node and initialize path analysis."""
        # Add filename debug info
        if self.debug:
            print(
                f"\n========== Starting analysis of file: {self.file_path} ==========\n"
            )

        self.path_root = PathNode(node)
        self.current_path = self.path_root
        super().generic_visit(node)

        # Print file info again upon analysis completion
        if self.debug:
            print(
                f"\n========== Completed analysis of file: {self.file_path} =========="
            )
            print(f"Found {len(self.found_sinks)} sinks")
            print(f"Found {len(self.found_sources)} sources")

    def visit_Assign(self, node: ast.Assign) -> None:
        """
        增强版的赋值访问，添加变量赋值跟踪
        """
        # 存储变量的赋值位置
        if hasattr(node, "lineno"):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    self.var_assignments[var_name] = {
                        "line": node.lineno,
                        "node": node,
                        "value": node.value,
                    }

                    # 检查是否从污点源获取值
                    if isinstance(node.value, ast.Call):
                        func_name, full_name = self._get_func_name_with_module(
                            node.value.func
                        )
                        if self._is_source(func_name, full_name):
                            if self.debug:
                                print(
                                    f"Found source assignment: {var_name} = {func_name} at line {node.lineno}"
                                )
                            # 记录源语句信息
                            source_type = self._get_source_type(func_name, full_name)
                            source_info = {
                                "name": source_type,
                                "line": node.lineno,
                                "col": node.col_offset,
                                "node": node,
                                "statement": self._get_node_source(node),
                            }
                            self.source_statements[var_name] = source_info

                            # 标记为污点变量
                            self.tainted[var_name] = source_info

        # 调用原始的赋值访问方法
        super().visit_Assign(node)

    def _get_node_source(self, node) -> str:
        """获取节点对应的源代码"""
        if (
            hasattr(node, "lineno")
            and self.source_lines
            and node.lineno <= len(self.source_lines)
        ):
            return self.source_lines[node.lineno - 1].strip()
        return ""

    def visit_Call(self, node: ast.Call) -> None:
        """
        Enhanced visit_Call to better track data flow and source propagation.
        """
        # 获取函数名称
        func_name, full_name = self._get_func_name_with_module(node.func)
        line_no = getattr(node, "lineno", 0)

        # 增强对特定污点源模式的识别
        if func_name == "recv" or "recv" in func_name:
            if self.debug:
                print(
                    f"Detected potential recv function: {func_name} at line {line_no}"
                )

            # 找出函数返回值的使用变量
            parent = self.parent_map.get(node)
            if parent and isinstance(parent, ast.Assign):
                for target in parent.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        if self.debug:
                            print(f"  Return value assigned to: {var_name}")

                        # 如果是已知的污点源，直接标记为污点
                        if self._is_source(func_name, full_name):
                            source_type = self._get_source_type(func_name, full_name)
                            source_info = {
                                "name": source_type,
                                "line": line_no,
                                "col": node.col_offset,
                                "node": node,
                                "statement": self._get_node_source(node),
                            }
                            self.tainted[var_name] = source_info
                            self.source_statements[var_name] = source_info
                            self.found_sources.append(source_info)

                            if self.debug:
                                print(
                                    f"  Marked {var_name} as tainted from source {source_type}"
                                )

        # 特殊追踪对已知污点变量的方法调用
        if isinstance(node.func, ast.Attribute) and isinstance(
            node.func.value, ast.Name
        ):
            var_name = node.func.value.id
            method_name = node.func.attr

            # 检查该变量是否已被污染
            if var_name in self.tainted:
                # 追踪方法链调用
                operation = f"{var_name}.{method_name}"
                if self.debug:
                    print(
                        f"Tracking method call on tainted variable: {operation} at line {line_no}"
                    )

                # 查找这个方法调用的父节点，看是否是赋值语句
                parent = self.parent_map.get(node)
                if parent and isinstance(parent, ast.Assign):
                    for target in parent.targets:
                        if isinstance(target, ast.Name):
                            # 污点传播到新变量
                            new_var = target.id
                            self.tainted[new_var] = self.tainted[var_name]
                            if self.debug:
                                print(f"  Taint propagated to: {new_var}")

        # 继续调用原始的Visit方法
        super().visit_Call(node)

    def _track_assignment_taint(self, node: ast.Call, source_info: Dict) -> None:
        """
        增强版的赋值污点跟踪，确保所有赋值都被正确跟踪
        """
        # 调用父类的方法
        super()._track_assignment_taint(node, source_info)

        # 增强对方法链的跟踪，例如 obj.numpy().tobytes()
        parent = self.parent_map.get(node)
        if isinstance(parent, ast.Attribute) or isinstance(parent, ast.Call):
            # 沿着调用链向上，寻找最终的赋值目标
            current = parent
            while current in self.parent_map:
                current_parent = self.parent_map.get(current)
                if isinstance(current_parent, ast.Assign):
                    # 找到了赋值语句
                    for target in current_parent.targets:
                        if isinstance(target, ast.Name):
                            var_name = target.id
                            self.tainted[var_name] = source_info
                            if self.debug:
                                print(
                                    f"Tracked taint to method chain result: {var_name}"
                                )
                    break
                current = current_parent

        # 特殊处理调用链中的return值传播
        if self.current_function:
            # 检查这个函数是否有返回语句
            for node in ast.walk(self.current_function.ast_node):
                if isinstance(node, ast.Return) and node.value:
                    # 如果返回值是一个变量，检查它是否被污染
                    if isinstance(node.value, ast.Name):
                        var_name = node.value.id
                        if var_name in self.tainted:
                            # 该函数返回了一个污点变量
                            self.current_function.return_tainted = True
                            self.current_function.return_taint_sources.append(
                                source_info
                            )
                            if self.debug:
                                print(
                                    f"Function {self.current_function.name} returns tainted value"
                                )

    def _get_func_name_with_module(self, node) -> Tuple[str, Optional[str]]:
        """Enhanced version of _get_func_name_with_module to handle more cases."""
        # Use parent method first
        func_name, full_name = super()._get_func_name_with_module(node)

        # Handle additional import cases
        if not full_name and func_name in self.module_imports:
            module, original_name = self.module_imports[func_name]
            full_name = f"{module}.{original_name}"

        return func_name, full_name
