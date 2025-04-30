"""
Enhanced AST visitor for taint analysis - Function related operations.
"""

import ast
import copy

from .visitor_base import EnhancedTaintVisitor
from .defuse import DefUseChain


class FunctionVisitorMixin:
    """Mixin for function-related visit methods."""

    def visit_FunctionDef(self: "EnhancedTaintVisitor", node: ast.FunctionDef) -> None:
        """Visit a function definition node to build call graph."""
        func_name = node.name
        start_line = getattr(node, "lineno", 0)
        end_line = getattr(node, "end_lineno", start_line)

        # Create function node if it doesn't exist
        if func_name not in self.functions:
            self.functions[func_name] = self.callgraph.CallGraphNode(
                func_name, node, self.file_path, start_line, end_line_no=end_line
            )
        else:
            # Update existing node with AST info
            self.functions[func_name].ast_node = node
            self.functions[func_name].file_path = self.file_path
            self.functions[func_name].line_no = start_line
            self.functions[func_name].end_line_no = end_line

        # Track parameters
        self.functions[func_name].parameters = []
        for arg in node.args.args:
            self.functions[func_name].parameters.append(arg.arg)

        previous_function = self.current_function
        self.current_function = self.functions[func_name]

        # Create new path node for this function
        function_path = self.pathsensitive.PathNode(node, self.current_path)
        self.current_path.add_child(function_path)
        old_path = self.current_path
        self.current_path = function_path

        # Save current state for restoration
        old_variable_taint = copy.deepcopy(self.variable_taint)

        # Check if any parameter is already tainted (through call sites)
        for i, param in enumerate(self.current_function.parameters):
            if i in self.current_function.tainted_parameters:
                # Add parameter to tainted variables with source info from the caller
                param_source_info = {
                    "name": "ParameterPassing",
                    "line": getattr(node, "lineno", 0),
                    "col": 0,
                }
                self.variable_taint[param] = param_source_info

                # Create def-use chain for parameter
                if param not in self.def_use_chains:
                    self.def_use_chains[param] = DefUseChain(param)
                self.def_use_chains[param].tainted = True
                self.def_use_chains[param].taint_sources.append(param_source_info)
                self.def_use_chains[param].add_definition(
                    node, getattr(node, "lineno", 0)
                )

        # Visit function body
        self.generic_visit(node)

        # Check if function returns tainted data
        self._check_function_return_taint(node)

        # Restore state
        self.current_function = previous_function
        self.current_path = old_path
        self.variable_taint = old_variable_taint

    def _check_function_return_taint(
        self: "EnhancedTaintVisitor", node: ast.FunctionDef
    ) -> None:
        """Check if a function returns tainted data."""
        returns_tainted = False
        taint_sources = []

        # Find all return statements
        return_nodes = []
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value:
                return_nodes.append(child)

        for return_node in return_nodes:
            # Check if returning a tainted variable directly
            if (
                isinstance(return_node.value, ast.Name)
                and return_node.value.id in self.variable_taint
            ):
                returns_tainted = True
                taint_sources.append(self.variable_taint[return_node.value.id])

            # Check for tainted expressions (could be expanded)
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

        # Update function's taint status
        self.current_function.return_tainted = returns_tainted
        self.current_function.return_taint_sources = taint_sources
        self.function_returns_tainted[self.current_function.name] = returns_tainted

        if returns_tainted and self.debug:
            print(
                f"Function {self.current_function.name} returns tainted data from sources: {taint_sources}"
            )

    def visit_Call(self: "EnhancedTaintVisitor", node: ast.Call) -> None:
        """Visit a call node with enhanced tracking."""
        # First run the original implementation from the base TaintVisitor
        super().visit_Call(node)

        # Get function name and full name
        func_name, full_name = self._get_func_name_with_module(node.func)

        if self.debug:
            print(
                f"Enhanced visit_Call: {func_name} (full: {full_name}) at line {getattr(node, 'lineno', 0)}"
            )

        # Track function calls for call graph
        if self.current_function and func_name:
            # Only add caller-callee relationship if the callee function
            # has been defined and visited (i.e., exists in self.functions).
            if func_name in self.functions:
                callee_node = self.functions[func_name]
                # Add caller-callee relationship using the existing node
                self.current_function.add_callee(callee_node)
                callee_node.add_caller(self.current_function)

                # Check for taint propagation through parameters only for known functions
                self._track_parameter_taint_propagation(node, func_name)
            else:
                # Optional: If needed for other call graph analysis, record the *name*
                # of the external callee without adding a node to self.functions.
                # Example: self.current_function.add_external_callee_name(func_name)
                if self.debug:
                    print(
                        f"  -> Call to external/undefined function '{func_name}' ignored for self.functions population."
                    )

        # Track taint propagation through return values
        self._track_return_taint_propagation(node, func_name)

        # Track complex data structure operations
        self._track_data_structure_operations(node, func_name, full_name)

        # Track container methods that may propagate taint
        self._track_container_methods(node)

        # Re-add generic_visit to ensure children (like arguments) are visited
        # *after* the enhanced logic in this method potentially modifies state.
        # The base class visit_Call also calls generic_visit, but calling it
        # here again ensures processing happens relative to the enhanced logic's state changes.
        self.generic_visit(node)

    def _track_parameter_taint_propagation(
        self: "EnhancedTaintVisitor", node: ast.Call, func_name: str
    ) -> None:
        """Track taint propagation through function parameters."""
        callee = self.functions[func_name]

        # Check positional arguments
        for i, arg in enumerate(node.args):
            if i < len(callee.parameters):  # Ensure parameter exists
                param_name = callee.parameters[i]

                # Check if argument is tainted
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
                    # Mark parameter as tainted in callee
                    callee.tainted_parameters.add(i)

                    # If we have callee's AST, propagate taint to its parameter
                    if callee.ast_node and i < len(callee.parameters):
                        param_taint_info = copy.deepcopy(source_info)

                        if self.debug:
                            print(
                                f"Propagated taint to parameter {param_name} in function {func_name}"
                            )

    def _track_return_taint_propagation(
        self: "EnhancedTaintVisitor", node: ast.Call, func_name: str
    ) -> None:
        """Track taint propagation through function return values."""
        # Check if this is a function that returns tainted data
        if (
            func_name in self.function_returns_tainted
            and self.function_returns_tainted[func_name]
        ):
            # Find the assignment this call is part of, if any
            if hasattr(node, "parent"):
                parent = node.parent

                # Check if call is part of an assignment
                if isinstance(parent, ast.Assign):
                    for target in parent.targets:
                        if isinstance(target, ast.Name):
                            # Propagate taint to target variable
                            return_taint_info = {
                                "name": "FunctionReturn",
                                "line": getattr(node, "lineno", 0),
                                "col": getattr(node, "col_offset", 0),
                            }

                            self.variable_taint[target.id] = return_taint_info

                            # Update def-use chain
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
                                print(
                                    f"Propagated taint from {func_name} return to {target.id}"
                                )

    def visit_With(self: "EnhancedTaintVisitor", node: ast.With) -> None:
        """
        Visit a with statement node to handle context managers.
        """
        for item in node.items:
            if isinstance(item.context_expr, ast.Call):
                # Get function name but don't hardcode any checks
                func_name, full_name = self._get_func_name_with_module(
                    item.context_expr.func
                )

                # Use configuration-driven approach to check if it's a file-related source
                is_file_open = False
                source_type = None

                # Check all source patterns
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

                # If it's a file open operation and has an as variable
                if (is_file_open or func_name == "open") and item.optional_vars:
                    if isinstance(item.optional_vars, ast.Name):
                        file_var = item.optional_vars.id

                        # Mark the file handle variable as tainted
                        source_info = {
                            "name": source_type or "FileRead",
                            "line": getattr(node, "lineno", 0),
                            "col": getattr(node, "col_offset", 0),
                            "context": "with_statement",
                        }

                        # Add file handle tracking
                        if not hasattr(self, "file_handles"):
                            self.file_handles = {}

                        # Mark tainted file handle from with statement
                        self.file_handles[file_var] = {
                            "source_var": "file_path",
                            "source_info": source_info,
                            "from_with": True,
                        }

                        # Explicitly mark file handle as tainted
                        self.variable_taint[file_var] = source_info

                        if self.debug:
                            print(
                                f"Marked file handle '{file_var}' as tainted (from with statement)"
                            )

        self.generic_visit(node)
