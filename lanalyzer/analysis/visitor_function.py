"""
Enhanced AST visitor for taint analysis - Function related operations.
"""

import ast
import copy

from .visitor_base import (
    EnhancedTaintVisitor,
)  # Assuming this will be resolved by the full context
from .defuse import DefUseChain  # Assuming this will be resolved by the full context
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

        if (
            not hasattr(self, "functions") or self.functions is None
        ):  # Ensure self.functions exists
            self.functions = {}
        if (
            not hasattr(self, "callgraph") or self.callgraph is None
        ):  # Ensure self.callgraph exists (mock or real)
            # Mock callgraph if not present, for standalone testing of the mixin
            class MockCallGraphNode:
                def __init__(self, name, ast_node, file_path, line_no, end_line_no):
                    self.name = name
                    self.ast_node = ast_node
                    self.file_path = file_path
                    self.line_no = line_no
                    self.end_line_no = end_line_no
                    self.parameters = []
                    self.callees = []
                    self.tainted_parameters = set()
                    self.return_tainted = False
                    self.return_taint_sources = []
                    self.self_method_calls = []

                def add_callee(self, callee):
                    pass

                def add_caller(self, caller):
                    pass

                def add_call_point(self, line, stmt, caller):
                    pass

            class MockCallGraph:
                CallGraphNode = MockCallGraphNode

                def add_self_method_call(self, c, m, line_no):
                    pass

            self.callgraph = MockCallGraph()

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
        for arg_def in node.args.args:
            self.functions[func_name].parameters.append(arg_def.arg)

        previous_function = self.current_function
        self.current_function = self.functions[func_name]

        if not hasattr(self, "pathsensitive"):  # Ensure pathsensitive exists
            # Mock pathsensitive if not present
            class MockPathNode:
                def __init__(self, node, parent=None):
                    pass

                def add_child(self, child):
                    pass

            class MockPathSensitive:
                PathNode = MockPathNode

            self.pathsensitive = MockPathSensitive()

        if (
            self.current_path is None
        ):  # current_path might not be initialized if entry is not Module
            self.current_path = self.pathsensitive.PathNode(
                node, None
            )  # Or handle appropriately

        function_path_node = self.pathsensitive.PathNode(node, self.current_path)
        self.current_path.add_child(function_path_node)
        old_path = self.current_path
        self.current_path = function_path_node

        old_variable_taint = copy.deepcopy(self.variable_taint)
        # Ensure self_method_calls attribute exists for the current function node
        if not hasattr(self.current_function, "self_method_calls"):
            self.current_function.self_method_calls = []

        for i, param_name_str in enumerate(self.current_function.parameters):
            if i in self.current_function.tainted_parameters:
                param_source_info_dict = {
                    "name": "ParameterPassing",
                    "line": getattr(node, "lineno", 0),
                    "col": 0,  # Placeholder, consider actual parameter col if available
                }
                self.variable_taint[param_name_str] = param_source_info_dict
                if param_name_str not in self.def_use_chains:
                    self.def_use_chains[param_name_str] = DefUseChain(param_name_str)
                self.def_use_chains[param_name_str].tainted = True
                self.def_use_chains[param_name_str].taint_sources.append(
                    param_source_info_dict
                )
                self.def_use_chains[param_name_str].add_definition(
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
                    f"[DEBUG] self.method() call statistics within Function '{self.current_function.name}':"
                )
                for call_info in self.current_function.self_method_calls:
                    debug(
                        f"  - self.{call_info['method']}() at line {call_info['line']} (call point: {call_info['call_statement']})"
                    )
            # New: Output callee method names of the current function
            if self.debug:
                callee_names = [
                    callee.name
                    for callee in getattr(self.current_function, "callees", [])
                ]
                debug(
                    f"[DEBUG] Callees of Function '{self.current_function.name}': {callee_names}"
                )
        self.current_function = previous_function
        self.current_path = old_path
        self.variable_taint = old_variable_taint

    def _check_function_return_taint(
        self: "EnhancedTaintVisitor", node: ast.FunctionDef
    ) -> None:
        """Check if a function returns tainted data."""
        returns_tainted_flag = False
        taint_sources_list = []
        return_nodes_list = []
        for child_node in ast.walk(node):
            if isinstance(child_node, ast.Return) and child_node.value:
                return_nodes_list.append(child_node)

        for return_stmt_node in return_nodes_list:
            value_node = return_stmt_node.value
            if (
                isinstance(value_node, ast.Name)
                and value_node.id in self.variable_taint
            ):
                returns_tainted_flag = True
                taint_sources_list.append(self.variable_taint[value_node.id])
            elif isinstance(value_node, ast.Call):
                called_func_name, _ = self._get_func_name_with_module(value_node.func)
                if (
                    called_func_name
                    and called_func_name in self.functions
                    and self.functions[called_func_name].return_tainted
                ):
                    returns_tainted_flag = True
                    taint_sources_list.extend(
                        self.functions[called_func_name].return_taint_sources
                    )

        if self.current_function:  # Ensure current_function is not None
            self.current_function.return_tainted = returns_tainted_flag
            self.current_function.return_taint_sources = taint_sources_list
            self.function_returns_tainted[
                self.current_function.name
            ] = returns_tainted_flag
            if returns_tainted_flag and self.debug:
                debug(
                    f"Function {self.current_function.name} returns tainted data from sources: {taint_sources_list}"
                )

    def visit_Call(self: "EnhancedTaintVisitor", node: ast.Call) -> None:
        """Visit a call node with enhanced tracking."""
        current_func_name = getattr(self.current_function, "name", "GlobalScope")
        debug(
            f"[FORCE] Enter visit_Call: in function {current_func_name}, call at line {getattr(node, 'lineno', None)}"
        )
        # It's important that super().visit_Call(node) is called appropriately
        # depending on whether this mixin overrides or supplements base behavior.
        # If it's meant to be called by the base, the base should call it.
        # If it's a full override, this is where it might call generic_visit or specific arg visits.
        # For now, assume it's called, and then we add more logic.
        # super().visit_Call(node) # This line might be needed if overriding a base class method
        # and wanting to call its logic. Removed for now as it's not standard in mixins
        # unless the MRO is specifically designed for it.

        func_name_str, full_name_str = self._get_func_name_with_module(node.func)

        if self.debug:
            debug(
                f"Enhanced visit_Call: {func_name_str} (full: {full_name_str}) at line {getattr(node, 'lineno', 0)}"
            )

        if self.current_function and func_name_str:
            if func_name_str in self.functions:
                callee_node_obj = self.functions[func_name_str]
                self.current_function.add_callee(callee_node_obj)
                callee_node_obj.add_caller(self.current_function)

                # Record call line number to build a more complete call chain
                call_line_num = getattr(node, "lineno", 0)
                # The callee_node_obj might be called from multiple places;
                # call_line on the node itself might represent the definition or last call.
                # Storing it in call_points is more robust.

                # Get call statement
                call_statement_str = self._get_call_source_code(call_line_num)

                # Add detailed call point information
                callee_node_obj.add_call_point(
                    call_line_num, call_statement_str, self.current_function.name
                )

                # Check if it is a self.method() call
                if isinstance(node.func, ast.Attribute) and isinstance(
                    node.func.value, ast.Name
                ):
                    if node.func.value.id == "self":
                        # Record this as a self method call
                        callee_node_obj.is_self_method_call = True
                        callee_node_obj.self_method_name = node.func.attr

                        if not hasattr(self, "self_method_call_map"):
                            self.self_method_call_map = {}
                        map_key = (
                            f"{self.current_function.name} -> self.{node.func.attr}"
                        )
                        self.self_method_call_map.setdefault(map_key, []).append(
                            call_line_num
                        )

                        if hasattr(self.current_function, "self_method_calls"):
                            self.current_function.self_method_calls.append(
                                {
                                    "method": node.func.attr,
                                    "line": call_line_num,
                                    "call_statement": call_statement_str,
                                }
                            )
                        if self.debug:
                            debug(
                                f"  -> Recorded self.{node.func.attr}() call at line {call_line_num} in {self.current_function.name}"
                            )
                        if hasattr(
                            self.callgraph, "add_self_method_call"
                        ):  # Check if callgraph module is fully loaded
                            self.callgraph.add_self_method_call(
                                self.current_function.name,
                                node.func.attr,
                                call_line_num,
                            )
                self._track_parameter_taint_propagation(node, func_name_str)
            else:
                if self.debug:
                    debug(
                        f"  -> Call to external/undefined function '{func_name_str}' at line {getattr(node, 'lineno', 0)} ignored for self.functions population."
                    )

        if func_name_str:  # Ensure func_name_str is not None
            self._track_return_taint_propagation(node, func_name_str)
            self._track_data_structure_operations(
                node, func_name_str, full_name_str
            )  # Assumes this method exists
            self._track_container_methods(node)  # Assumes this method exists

        self.generic_visit(
            node
        )  # Process arguments and other children of the Call node

    def _track_parameter_taint_propagation(
        self: "EnhancedTaintVisitor", node: ast.Call, func_name: str
    ) -> None:
        """Track taint propagation through function parameters."""
        if func_name not in self.functions:
            return

        callee = self.functions[func_name]
        for i, arg_node in enumerate(node.args):
            if i < len(callee.parameters):
                param_name = callee.parameters[i]
                is_tainted = False
                arg_source_info = None
                if (
                    isinstance(arg_node, ast.Name)
                    and arg_node.id in self.variable_taint
                ):
                    is_tainted = True
                    arg_source_info = self.variable_taint[arg_node.id]
                elif isinstance(arg_node, ast.Call):
                    inner_func_name, _ = self._get_func_name_with_module(arg_node.func)
                    if (
                        inner_func_name
                        and inner_func_name in self.function_returns_tainted
                        and self.function_returns_tainted[inner_func_name]
                    ):
                        is_tainted = True
                        arg_source_info = {
                            "name": "FunctionReturn",
                            "function": inner_func_name,  # Added for more context
                            "line": getattr(arg_node, "lineno", 0),
                            "col": getattr(arg_node, "col_offset", 0),
                        }
                if is_tainted and arg_source_info:
                    callee.tainted_parameters.add(i)
                    # Propagating taint to callee's parameter context would happen when visiting the callee.
                    # Here, we're marking the callee node's parameter as receiving taint.
                    if self.debug:
                        debug(
                            f"Propagated taint via argument '{ast.unparse(arg_node) if hasattr(ast, 'unparse') else 'arg'}' to parameter '{param_name}' (index {i}) in function '{func_name}'"
                        )

    def _track_return_taint_propagation(
        self: "EnhancedTaintVisitor", node: ast.Call, func_name: str
    ) -> None:
        """Track taint propagation through function return values."""
        if (
            func_name
            and func_name in self.function_returns_tainted
            and self.function_returns_tainted[func_name]
        ):
            # Check if the call is part of an assignment
            parent_node = getattr(
                node, "parent", None
            )  # Ensure parent is set by a prior pass or method
            if isinstance(parent_node, ast.Assign):
                for target_node in parent_node.targets:
                    if isinstance(target_node, ast.Name):
                        var_name = target_node.id
                        return_source_info = {
                            "name": "FunctionReturn",
                            "function": func_name,  # Added for more context
                            "line": getattr(node, "lineno", 0),  # Line of the call
                            "col": getattr(node, "col_offset", 0),
                        }
                        self.variable_taint[var_name] = return_source_info
                        if var_name not in self.def_use_chains:
                            self.def_use_chains[var_name] = DefUseChain(var_name)
                        self.def_use_chains[var_name].tainted = True
                        self.def_use_chains[var_name].taint_sources.append(
                            return_source_info
                        )
                        self.def_use_chains[var_name].add_definition(
                            parent_node, getattr(parent_node, "lineno", 0)
                        )
                        if self.debug:
                            debug(
                                f"Propagated taint from return of '{func_name}' to variable '{var_name}'"
                            )

    def visit_With(self: "EnhancedTaintVisitor", node: ast.With) -> None:
        """
        Visit a with statement node to handle context managers, especially file operations.
        """
        for item in node.items:
            if isinstance(item.context_expr, ast.Call):
                # Assuming _get_func_name_with_module and self.sources are available
                func_name_str, full_name_str = self._get_func_name_with_module(
                    item.context_expr.func
                )

                is_file_operation = False
                source_type_str = None

                # Check against configured sources
                if hasattr(self, "sources"):
                    for source_config in self.sources:
                        for pattern in source_config.get("patterns", []):
                            if (
                                pattern == func_name_str
                                or (full_name_str and pattern in full_name_str)
                                or ("open" in pattern and func_name_str == "open")
                            ):  # More specific check for open
                                is_file_operation = True
                                source_type_str = source_config.get("name", "FileRead")
                                break
                        if is_file_operation:
                            break

                # Fallback for common 'open' call
                if not is_file_operation and func_name_str == "open":
                    is_file_operation = True
                    source_type_str = "FileRead"

                if is_file_operation and item.optional_vars:
                    if isinstance(item.optional_vars, ast.Name):
                        file_var_name = item.optional_vars.id
                        file_op_source_info = {
                            "name": source_type_str or "FileRead",
                            "detail": f"Opened via 'with {func_name_str}(...)'",
                            "line": getattr(node, "lineno", 0),
                            "col": getattr(node, "col_offset", 0),
                            "context": "with_statement",
                        }
                        if not hasattr(self, "file_handles"):
                            self.file_handles = {}
                        self.file_handles[file_var_name] = {
                            # 'source_var' might refer to the filename argument if available
                            "source_info": file_op_source_info,
                            "from_with": True,
                        }
                        self.variable_taint[file_var_name] = file_op_source_info
                        if self.debug:
                            debug(
                                f"Marked file handle '{file_var_name}' as tainted (from 'with {func_name_str}' statement)"
                            )
        self.generic_visit(node)

    # Add new helper method to extract source code at a specific call location
    def _get_call_source_code(self: "EnhancedTaintVisitor", line_no: int) -> str:
        """Get the source code for a specific line number"""
        if (
            hasattr(self, "source_lines")
            and self.source_lines
            and 0 < line_no <= len(self.source_lines)
        ):
            return self.source_lines[line_no - 1].strip()
        return "Source line not available"

    # These methods might be part of the main visitor class rather than a mixin,
    # or the mixin is used by a class that does not define them.
    # If they are intended to be overridden by the mixin, `super().visit_Module(node)` would be used.
    # For now, just translate them as provided.

    def visit_Module(self: "EnhancedTaintVisitor", node: ast.Module) -> None:
        """Visit a module node."""  # Simple English docstring
        debug(
            f"[FORCE] Enter visit_Module (FunctionVisitorMixin): {getattr(self, 'file_path', 'Unknown File')}"
        )
        self.generic_visit(node)  # Basic behavior: visit children

    def visit_ClassDef(self: "EnhancedTaintVisitor", node: ast.ClassDef) -> None:
        """Visit a class definition node."""  # Simple English docstring
        debug(
            f"[FORCE] Enter visit_ClassDef (FunctionVisitorMixin): {getattr(node, 'name', 'Unnamed Class')}"
        )
        # Output the type and name of all members under the class
        if self.debug:
            for item in node.body:
                item_type = type(item).__name__
                item_name = getattr(item, "name", "Unnamed member")
                debug(
                    f"[FORCE] Class member (FunctionVisitorMixin view): type={item_type}, name={item_name}"
                )
        self.generic_visit(node)  # Basic behavior: visit children
