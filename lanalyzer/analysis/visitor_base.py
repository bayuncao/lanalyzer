"""
Enhanced AST visitor for taint analysis - Base Visitor.
"""

import ast
import os
from typing import Callable, Dict, Optional, Tuple

from lanalyzer.analysis.ast_parser import TaintVisitor
from lanalyzer.logger import debug, info, warning, error

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
        debug_mode: bool = False,
        verbose: bool = False,
        file_path: Optional[str] = None,
    ):
        """
        Initialize the enhanced taint visitor.

        Args:
            parent_map: Dictionary mapping AST nodes to their parents
            debug_mode: Whether to enable debug output
            verbose: Whether to enable verbose output
            file_path: Path to the file being analyzed
        """
        super().__init__(parent_map, debug_mode, verbose)
        self.file_path = file_path
        self.source_lines = None
        self.debug = debug_mode

        if file_path and os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    self.source_lines = f.readlines()
                if self.debug:
                    debug(f"从 {file_path} 加载了 {len(self.source_lines)} 行源代码")
            except Exception as e:
                if self.debug:
                    error(f"加载源代码失败: {str(e)}")

        self.variable_taint = self.tainted if hasattr(self, "tainted") else {}
        self.sources = []
        self.sinks = []
        self.source_statements = {}
        self.functions = {}
        self.current_function = None
        self.call_locations = []
        self.data_structures = {}
        self.def_use_chains = {}
        self.path_root = None
        self.current_path = None
        self.path_constraints = []
        self.function_returns_tainted = {}
        self.module_imports = {}
        self.file_handle_operations = {}
        self.operation_taint_rules = self._initialize_operation_taint_rules()
        self.data_flow_targets = {}
        self.var_assignments = {}
        self.var_uses = {}
        if self.debug:
            debug(f"创建 EnhancedTaintVisitor 实例分析文件: {self.file_path}")

    def _initialize_operation_taint_rules(self) -> Dict[str, Callable]:
        """Initialize rules for how taint propagates through different operations."""
        rules = {}
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
        container_propagating_methods = ["copy", "items", "keys", "values"]
        for method in container_propagating_methods:
            rules[f"dict.{method}"] = lambda node, source_info: source_info
            rules[f"list.{method}"] = lambda node, source_info: source_info
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
        if self.debug:
            debug(f"\n========== 开始分析文件: {self.file_path} ==========\n")
        self.path_root = PathNode(node)
        self.current_path = self.path_root
        super().generic_visit(node)
        if self.debug:
            debug(f"\n========== 完成分析文件: {self.file_path} ==========")
            debug(f"发现 {len(self.found_sinks)} 个汇聚点")
            debug(f"发现 {len(self.found_sources)} 个源点")

    def visit_Assign(self, node: ast.Assign) -> None:
        """
        Enhanced assignment visit with variable assignment tracking.
        """
        if hasattr(node, "lineno"):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    self.var_assignments[var_name] = {
                        "line": node.lineno,
                        "node": node,
                        "value": node.value,
                    }
                    if isinstance(node.value, ast.Call):
                        func_name, full_name = self._get_func_name_with_module(
                            node.value.func
                        )
                        if self._is_source(func_name, full_name):
                            if self.debug:
                                debug(
                                    f"发现源赋值: {var_name} = {func_name} 在第 {node.lineno} 行"
                                )
                            source_type = self._get_source_type(func_name, full_name)
                            source_info = {
                                "name": source_type,
                                "line": node.lineno,
                                "col": node.col_offset,
                                "node": node,
                                "statement": self._get_node_source(node),
                            }
                            self.source_statements[var_name] = source_info
                            self.tainted[var_name] = source_info
        super().visit_Assign(node)

    def _get_node_source(self, node) -> str:
        """Get the source code for a node."""
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
        func_name, full_name = self._get_func_name_with_module(node.func)
        line_no = getattr(node, "lineno", 0)
        if func_name == "recv" or "recv" in func_name:
            if self.debug:
                print(
                    f"Detected potential recv function: {func_name} at line {line_no}"
                )
            parent = self.parent_map.get(node)
            if parent and isinstance(parent, ast.Assign):
                for target in parent.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        if self.debug:
                            print(f"  Return value assigned to: {var_name}")
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
        if isinstance(node.func, ast.Attribute) and isinstance(
            node.func.value, ast.Name
        ):
            var_name = node.func.value.id
            method_name = node.func.attr
            if var_name in self.tainted:
                operation = f"{var_name}.{method_name}"
                if self.debug:
                    print(
                        f"Tracking method call on tainted variable: {operation} at line {line_no}"
                    )
                parent = self.parent_map.get(node)
                if parent and isinstance(parent, ast.Assign):
                    for target in parent.targets:
                        if isinstance(target, ast.Name):
                            new_var = target.id
                            self.tainted[new_var] = self.tainted[var_name]
                            if self.debug:
                                print(f"  Taint propagated to: {new_var}")
        super().visit_Call(node)

    def _track_assignment_taint(self, node: ast.Call, source_info: Dict) -> None:
        """
        Enhanced assignment taint tracking to ensure all assignments are tracked.
        """
        super()._track_assignment_taint(node, source_info)
        parent = self.parent_map.get(node)
        if isinstance(parent, ast.Attribute) or isinstance(parent, ast.Call):
            current = parent
            while current in self.parent_map:
                current_parent = self.parent_map.get(current)
                if isinstance(current_parent, ast.Assign):
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
        if self.current_function:
            for node in ast.walk(self.current_function.ast_node):
                if isinstance(node, ast.Return) and node.value:
                    if isinstance(node.value, ast.Name):
                        var_name = node.value.id
                        if var_name in self.tainted:
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
        func_name, full_name = super()._get_func_name_with_module(node)
        if not full_name and func_name in self.module_imports:
            module, original_name = self.module_imports[func_name]
            full_name = f"{module}.{original_name}"
        return func_name, full_name
