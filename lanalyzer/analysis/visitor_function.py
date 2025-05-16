"""
Enhanced AST visitor for taint analysis - Function related operations.
"""

import ast
import copy

from .visitor_base import EnhancedTaintVisitor
from .defuse import DefUseChain
from lanalyzer.logger import debug


class FunctionVisitorMixin:
    """Mixin for function-related visit methods."""

    def visit_FunctionDef(self: "EnhancedTaintVisitor", node: ast.FunctionDef) -> None:
        """Visit a function definition node to build call graph."""
        debug(
            f"[FORCE] Enter visit_FunctionDef: {getattr(node, 'name', None)}, self.debug={getattr(self, 'debug', None)}"
        )
        func_name = node.name
        start_line = getattr(node, "lineno", 0)
        end_line = getattr(node, "end_lineno", start_line)
        if func_name not in self.functions:
            self.functions[func_name] = self.callgraph.CallGraphNode(
                func_name, node, self.file_path, start_line, end_line_no=end_line
            )
        else:
            self.functions[func_name].ast_node = node
            self.functions[func_name].file_path = self.file_path
            self.functions[func_name].line_no = start_line
            self.functions[func_name].end_line_no = end_line
        self.functions[func_name].parameters = []
        for arg in node.args.args:
            self.functions[func_name].parameters.append(arg.arg)
        previous_function = self.current_function
        self.current_function = self.functions[func_name]
        if self.current_path is None:
            self.current_path = self.pathsensitive.PathNode(node, None)
        function_path = self.pathsensitive.PathNode(node, self.current_path)
        self.current_path.add_child(function_path)
        old_path = self.current_path
        self.current_path = function_path
        old_variable_taint = copy.deepcopy(self.variable_taint)
        self.current_function.self_method_calls = []
        for i, param in enumerate(self.current_function.parameters):
            if i in self.current_function.tainted_parameters:
                param_source_info = {
                    "name": "ParameterPassing",
                    "line": getattr(node, "lineno", 0),
                    "col": 0,
                }
                self.variable_taint[param] = param_source_info
                if param not in self.def_use_chains:
                    self.def_use_chains[param] = DefUseChain(param)
                self.def_use_chains[param].tainted = True
                self.def_use_chains[param].taint_sources.append(param_source_info)
                self.def_use_chains[param].add_definition(
                    node, getattr(node, "lineno", 0)
                )
        self.generic_visit(node)
        self._check_function_return_taint(node)
        if (
            hasattr(self.current_function, "self_method_calls")
            and self.current_function.self_method_calls
        ):
            if self.debug:
                debug(
                    f"[DEBUG] Function '{self.current_function.name}' 内 self.method() 调用统计："
                )
                for call in self.current_function.self_method_calls:
                    debug(
                        f"  - self.{call['method']}() at line {call['line']} (调用点: {call['call_statement']})"
                    )
            # 新增：输出当前函数的 callees 方法名
            if self.debug:
                callee_names = [
                    callee.name
                    for callee in getattr(self.current_function, "callees", [])
                ]
                debug(
                    f"[DEBUG] Function '{self.current_function.name}' 的 callees: {callee_names}"
                )
        self.current_function = previous_function
        self.current_path = old_path
        self.variable_taint = old_variable_taint

    def _check_function_return_taint(
        self: "EnhancedTaintVisitor", node: ast.FunctionDef
    ) -> None:
        """Check if a function returns tainted data."""
        returns_tainted = False
        taint_sources = []
        return_nodes = []
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value:
                return_nodes.append(child)
        for return_node in return_nodes:
            if (
                isinstance(return_node.value, ast.Name)
                and return_node.value.id in self.variable_taint
            ):
                returns_tainted = True
                taint_sources.append(self.variable_taint[return_node.value.id])
            elif isinstance(return_node.value, ast.Call):
                func_name, full_name = self._get_func_name_with_module(
                    return_node.value.func
                )
                if (
                    func_name in self.functions
                    and self.functions[func_name].return_tainted
                ):
                    returns_tainted = True
                    taint_sources.extend(self.functions[func_name].return_taint_sources)
        self.current_function.return_tainted = returns_tainted
        self.current_function.return_taint_sources = taint_sources
        self.function_returns_tainted[self.current_function.name] = returns_tainted
        if returns_tainted and self.debug:
            debug(
                f"Function {self.current_function.name} returns tainted data from sources: {taint_sources}"
            )

    def visit_Call(self: "EnhancedTaintVisitor", node: ast.Call) -> None:
        """Visit a call node with enhanced tracking."""
        debug(
            f"[FORCE] Enter visit_Call: in function {getattr(self, 'current_function', None) and self.current_function.name}, call at line {getattr(node, 'lineno', None)}"
        )
        super().visit_Call(node)
        func_name, full_name = self._get_func_name_with_module(node.func)
        if self.debug:
            debug(
                f"Enhanced visit_Call: {func_name} (full: {full_name}) at line {getattr(node, 'lineno', 0)}"
            )
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
                self._track_parameter_taint_propagation(node, func_name)
            else:
                if self.debug:
                    debug(
                        f"  -> Call to external/undefined function '{func_name}' ignored for self.functions population."
                    )
        self._track_return_taint_propagation(node, func_name)
        self._track_data_structure_operations(node, func_name, full_name)
        self._track_container_methods(node)
        self.generic_visit(node)

    def _track_parameter_taint_propagation(
        self: "EnhancedTaintVisitor", node: ast.Call, func_name: str
    ) -> None:
        """Track taint propagation through function parameters."""
        callee = self.functions[func_name]
        for i, arg in enumerate(node.args):
            if i < len(callee.parameters):
                param_name = callee.parameters[i]
                tainted = False
                source_info = None
                if isinstance(arg, ast.Name) and arg.id in self.variable_taint:
                    tainted = True
                    source_info = self.variable_taint[arg.id]
                elif isinstance(arg, ast.Call):
                    inner_func_name, inner_full_name = self._get_func_name_with_module(
                        arg.func
                    )
                    if (
                        inner_func_name in self.function_returns_tainted
                        and self.function_returns_tainted[inner_func_name]
                    ):
                        tainted = True
                        source_info = {
                            "name": "FunctionReturn",
                            "line": getattr(arg, "lineno", 0),
                            "col": getattr(arg, "col_offset", 0),
                        }
                if tainted and source_info:
                    callee.tainted_parameters.add(i)
                    if callee.ast_node and i < len(callee.parameters):
                        param_taint_info = copy.deepcopy(source_info)
                        if self.debug:
                            debug(
                                f"Propagated taint to parameter {param_name} in function {func_name}"
                            )

    def _track_return_taint_propagation(
        self: "EnhancedTaintVisitor", node: ast.Call, func_name: str
    ) -> None:
        """Track taint propagation through function return values."""
        if (
            func_name in self.function_returns_tainted
            and self.function_returns_tainted[func_name]
        ):
            if hasattr(node, "parent"):
                parent = node.parent
                if isinstance(parent, ast.Assign):
                    for target in parent.targets:
                        if isinstance(target, ast.Name):
                            return_taint_info = {
                                "name": "FunctionReturn",
                                "line": getattr(node, "lineno", 0),
                                "col": getattr(node, "col_offset", 0),
                            }
                            self.variable_taint[target.id] = return_taint_info
                            if target.id not in self.def_use_chains:
                                self.def_use_chains[target.id] = DefUseChain(target.id)
                            self.def_use_chains[target.id].tainted = True
                            self.def_use_chains[target.id].taint_sources.append(
                                return_taint_info
                            )
                            self.def_use_chains[target.id].add_definition(
                                parent, getattr(parent, "lineno", 0)
                            )
                            if self.debug:
                                debug(
                                    f"Propagated taint from {func_name} return to {target.id}"
                                )

    def visit_With(self: "EnhancedTaintVisitor", node: ast.With) -> None:
        """
        Visit a with statement node to handle context managers.
        """
        for item in node.items:
            if isinstance(item.context_expr, ast.Call):
                func_name, full_name = self._get_func_name_with_module(
                    item.context_expr.func
                )
                is_file_open = False
                source_type = None
                for source in self.sources:
                    for pattern in source["patterns"]:
                        if (
                            pattern == func_name
                            or (full_name and pattern in full_name)
                            or ("open" in pattern)
                        ):
                            is_file_open = True
                            source_type = source["name"]
                            break
                    if is_file_open:
                        break
                if (is_file_open or func_name == "open") and item.optional_vars:
                    if isinstance(item.optional_vars, ast.Name):
                        file_var = item.optional_vars.id
                        source_info = {
                            "name": source_type or "FileRead",
                            "line": getattr(node, "lineno", 0),
                            "col": getattr(node, "col_offset", 0),
                            "context": "with_statement",
                        }
                        if not hasattr(self, "file_handles"):
                            self.file_handles = {}
                        self.file_handles[file_var] = {
                            "source_var": "file_path",
                            "source_info": source_info,
                            "from_with": True,
                        }
                        self.variable_taint[file_var] = source_info
                        if self.debug:
                            debug(
                                f"Marked file handle '{file_var}' as tainted (from with statement)"
                            )
        self.generic_visit(node)

    # 添加新的辅助方法来提取特定调用位置的源代码
    def _get_call_source_code(self: "EnhancedTaintVisitor", line_no: int) -> str:
        """获取特定行号的源代码"""
        if (
            hasattr(self, "source_lines")
            and self.source_lines
            and 0 < line_no <= len(self.source_lines)
        ):
            return self.source_lines[line_no - 1].strip()
        return ""

    def visit_Module(self: "EnhancedTaintVisitor", node: ast.Module) -> None:
        debug(f"[FORCE] Enter visit_Module: {getattr(self, 'file_path', None)}")
        self.generic_visit(node)

    def visit_ClassDef(self: "EnhancedTaintVisitor", node: ast.ClassDef) -> None:
        debug(f"[FORCE] Enter visit_ClassDef: {getattr(node, 'name', None)}")
        # 输出类下所有成员的类型和名称
        for item in node.body:
            item_type = type(item).__name__
            item_name = getattr(item, "name", None)
            debug(f"[FORCE] Class member: type={item_type}, name={item_name}")
        self.generic_visit(node)
