"""
Enhanced AST visitor for taint analysis - Base Visitor.
"""

import ast
import os
from typing import Callable, Dict, Optional, Tuple

from lanalyzer.analysis.ast_parser import TaintVisitor
from lanalyzer.logger import debug, error

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

        # Try to get configuration from attached config
        config = getattr(self, "config", {})
        taint_rules = {}

        # Load from config if available
        if hasattr(self, "config") and isinstance(self.config, dict):
            # Try to get from a global config object
            if "operation_taint_rules" in self.config:
                taint_rules = self.config["operation_taint_rules"]

        # Get string methods from config or use defaults
        string_propagating_methods = taint_rules.get(
            "string_methods",
            [
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
            ],
        )

        for method in string_propagating_methods:
            rules[f"str.{method}"] = lambda node, source_info: source_info

        # Get container methods from config or use defaults
        container_methods = taint_rules.get("container_methods", {})
        dict_methods = container_methods.get(
            "dict", ["copy", "items", "keys", "values"]
        )
        list_methods = container_methods.get(
            "list", ["copy", "items", "keys", "values"]
        )

        for method in dict_methods:
            rules[f"dict.{method}"] = lambda node, source_info: source_info

        for method in list_methods:
            rules[f"list.{method}"] = lambda node, source_info: source_info

        # Get data methods from config or use defaults
        data_propagating_methods = taint_rules.get(
            "data_methods",
            [
                "numpy",
                "tobytes",
                "tensor",
                "array",
                "astype",
                "decode",
                "encode",
            ],
        )

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
        Also handles function call graph construction and self.method() calls.
        """
        # 记录调试信息
        debug(
            f"[FORCE] Enter visit_Call: in function {getattr(self, 'current_function', None) and self.current_function.name}, call at line {getattr(node, 'lineno', None)}"
        )

        # 原始EnhancedTaintVisitor.visit_Call的功能 - 数据流分析
        func_name, full_name = self._get_func_name_with_module(node.func)
        line_no = getattr(node, "lineno", 0)
        if func_name == "recv" or "recv" in func_name:
            if self.debug:
                debug(
                    f"Detected potential recv function: {func_name} at line {line_no}"
                )
            parent = self.parent_map.get(node)
            if parent and isinstance(parent, ast.Assign):
                for target in parent.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        if self.debug:
                            debug(f"  Return value assigned to: {var_name}")
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
                                debug(
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
                    debug(
                        f"Tracking method call on tainted variable: {operation} at line {line_no}"
                    )
                parent = self.parent_map.get(node)
                if parent and isinstance(parent, ast.Assign):
                    for target in parent.targets:
                        if isinstance(target, ast.Name):
                            new_var = target.id
                            self.tainted[new_var] = self.tainted[var_name]
                            if self.debug:
                                debug(f"  Taint propagated to: {new_var}")

        # 从FunctionVisitorMixin.visit_Call集成的功能 - 函数调用图构建
        if self.debug:
            debug(
                f"Enhanced visit_Call: {func_name} (full: {full_name}) at line {getattr(node, 'lineno', 0)}"
            )

        # 增加函数调用图的构建逻辑
        if self.current_function and func_name:
            if func_name in self.functions:
                callee_node = self.functions[func_name]
                self.current_function.add_callee(callee_node)
                callee_node.add_caller(self.current_function)

                # 记录调用行号,用于构建更完整的调用链
                call_line = getattr(node, "lineno", 0)
                callee_node.call_line = call_line

                # 获取调用语句
                call_statement = self._get_call_source_code(call_line)

                # 添加详细的调用点信息
                callee_node.add_call_point(
                    call_line, call_statement, self.current_function.name
                )

                # 检查是否是self.method()调用
                is_self_method_call = False
                if isinstance(node.func, ast.Attribute) and isinstance(
                    node.func.value, ast.Name
                ):
                    if node.func.value.id == "self":
                        is_self_method_call = True
                        # 记录这是一个self方法调用
                        callee_node.is_self_method_call = True
                        callee_node.self_method_name = node.func.attr
                        if not hasattr(self, "self_method_call_map"):
                            self.self_method_call_map = {}
                        key = f"{self.current_function.name} -> self.{node.func.attr}"
                        self.self_method_call_map.setdefault(key, []).append(call_line)
                        if hasattr(self.current_function, "self_method_calls"):
                            self.current_function.self_method_calls.append(
                                {
                                    "method": node.func.attr,
                                    "line": call_line,
                                    "call_statement": call_statement,
                                }
                            )
                        if self.debug:
                            debug(
                                f"  -> Recorded self.{node.func.attr}() call at line {call_line} in {self.current_function.name}"
                            )
                        if hasattr(self.callgraph, "add_self_method_call"):
                            self.callgraph.add_self_method_call(
                                self.current_function.name, node.func.attr, call_line
                            )

                # 跟踪参数污点传播
                if hasattr(self, "_track_parameter_taint_propagation"):
                    self._track_parameter_taint_propagation(node, func_name)
            else:
                if self.debug:
                    debug(
                        f"  -> Call to external/undefined function '{func_name}' ignored for self.functions population."
                    )

        # 返回值污点传播
        if hasattr(self, "_track_return_taint_propagation"):
            self._track_return_taint_propagation(node, func_name)

        # 数据结构操作跟踪
        if hasattr(self, "_track_data_structure_operations"):
            self._track_data_structure_operations(node, func_name, full_name)

        # 容器方法跟踪
        if hasattr(self, "_track_container_methods"):
            self._track_container_methods(node)

        # 调用父类的visit_Call方法，确保sink检测逻辑被执行
        super().visit_Call(node)

    # 添加辅助方法来提取特定调用位置的源代码
    def _get_call_source_code(self, line_no: int) -> str:
        """获取特定行号的源代码"""
        if (
            hasattr(self, "source_lines")
            and self.source_lines
            and 0 < line_no <= len(self.source_lines)
        ):
            return self.source_lines[line_no - 1].strip()
        return ""

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
                                debug(
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
                                debug(
                                    f"Function {self.current_function.name} returns tainted value"
                                )

    def _get_func_name_with_module(self, node) -> Tuple[str, Optional[str]]:
        """Enhanced version of _get_func_name_with_module to handle more cases."""
        func_name, full_name = super()._get_func_name_with_module(node)
        if not full_name and func_name in self.module_imports:
            module, original_name = self.module_imports[func_name]
            full_name = f"{module}.{original_name}"
        return func_name, full_name
