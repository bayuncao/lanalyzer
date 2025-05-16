"""
Enhanced AST visitor for taint analysis - Base Visitor.
"""

import ast
import os
from typing import (
    Callable,
    Dict,
    Optional,
    Tuple,
    List,
    Any,
    Union,
)  # Added List, Any, Union for type hints

from lanalyzer.analysis.ast_parser import (
    TaintVisitor,
)  # Assuming this base class exists
from lanalyzer.logger import debug, error

from .pathsensitive import PathNode  # Assuming this module and class exist


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
        parent_map: Optional[Dict[ast.AST, ast.AST]] = None,  # Type hinted parent_map
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
        self.file_path: Optional[str] = file_path
        self.source_lines: Optional[List[str]] = None
        self.debug: bool = debug_mode

        if file_path and os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    self.source_lines = f.readlines()
                if self.debug:
                    debug(
                        f"Loaded {len(self.source_lines)} lines of source code from {file_path}"
                    )
            except Exception as e:
                if self.debug:
                    error(f"Failed to load source code: {str(e)}")

        self.variable_taint: Dict[str, Any] = (
            self.tainted if hasattr(self, "tainted") else {}
        )  # self.tainted is from TaintVisitor
        self.sources: List[Dict[str, Any]] = []  # Assuming structure from context
        self.sinks: List[Dict[str, Any]] = []  # Assuming structure from context
        self.source_statements: Dict[str, Any] = {}
        self.functions: Dict[str, Any] = {}  # Usually Dict[str, CallGraphNode]
        self.current_function: Optional[Any] = None  # Usually Optional[CallGraphNode]
        self.call_locations: List[Any] = []
        self.data_structures: Dict[str, Any] = {}
        self.def_use_chains: Dict[str, Any] = {}  # Usually Dict[str, DefUseChain]
        self.path_root: Optional[PathNode] = None
        self.current_path: Optional[PathNode] = None
        self.path_constraints: List[Any] = []
        self.function_returns_tainted: Dict[str, bool] = {}
        self.module_imports: Dict[str, Tuple[str, str]] = {}
        self.file_handle_operations: Dict[str, Any] = {}  # Tracking file handles
        self.operation_taint_rules: Dict[
            str, Callable
        ] = self._initialize_operation_taint_rules()
        self.data_flow_targets: Dict[str, Any] = {}
        self.var_assignments: Dict[str, Any] = {}
        self.var_uses: Dict[str, Any] = {}

        # Attributes from TaintVisitor that might be used by methods here
        if not hasattr(self, "found_sinks"):
            self.found_sinks: List[Any] = []
        if not hasattr(self, "found_sources"):
            self.found_sources: List[Any] = []

        if self.debug:
            debug(
                f"Created EnhancedTaintVisitor instance to analyze file: {self.file_path}"
            )

    def _initialize_operation_taint_rules(self) -> Dict[str, Callable]:
        """Initialize rules for how taint propagates through different operations."""
        rules: Dict[str, Callable] = {}

        # Try to get configuration from attached config
        config = getattr(self, "config", {})  # type: ignore
        taint_rules_config: Dict[str, Any] = {}

        # Load from config if available
        if isinstance(config, dict):  # Check if config is a dict
            # Try to get from a global config object
            if "operation_taint_rules" in config:
                taint_rules_config = config["operation_taint_rules"]

        # Get string methods from config or use defaults
        string_propagating_methods: List[str] = taint_rules_config.get(
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
                # Common string operations that preserve taint
                "__add__",
                "__mul__",  # str concatenation and repetition
            ],
        )

        for method in string_propagating_methods:
            rules[
                f"str.{method}"
            ] = lambda node, source_info: source_info  # Taint propagates

        # Get container methods from config or use defaults
        container_methods_config: Dict[str, List[str]] = taint_rules_config.get(
            "container_methods", {}
        )
        dict_propagating_methods: List[str] = container_methods_config.get(
            "dict", ["copy", "items", "keys", "values", "get", "pop", "popitem"]
        )
        list_propagating_methods: List[str] = container_methods_config.get(
            "list",
            [
                "copy",
                "append",
                "extend",
                "insert",
                "pop",
                "remove",
                "sort",
                "reverse",
                "__getitem__",
            ],
        )  # Note: some list methods modify in place, some return new. Behavior needs care.

        for method in dict_propagating_methods:
            rules[
                f"dict.{method}"
            ] = lambda node, source_info: source_info  # Taint propagates

        for method in list_propagating_methods:
            rules[
                f"list.{method}"
            ] = lambda node, source_info: source_info  # Taint propagates

        # Get data methods from config or use defaults for libraries like numpy, pandas
        data_propagating_methods: List[str] = taint_rules_config.get(
            "data_methods",
            [
                "numpy.array",
                "pandas.DataFrame",
                "pandas.Series",  # Creation
                "tobytes",
                "decode",
                "encode",  # Encoding/Decoding
                # Common DataFrame/Series methods that might propagate taint
                "astype",
                "copy",
                "values",
                "iterrows",
                "itertuples",
                "apply",
                "map",
                "__getitem__",  # Accessing elements
            ],
        )

        for (
            method_path
        ) in data_propagating_methods:  # Can be module.method or just method
            rules[
                method_path
            ] = lambda node, source_info: source_info  # Taint propagates

        return rules

    def visit_Module(self, node: ast.Module) -> None:
        """Visit a module node and initialize path analysis."""
        if self.debug:
            debug(
                f"\n========== Starting analysis of file: {self.file_path} ==========\n"
            )
        self.path_root = PathNode(node)  # Assuming PathNode is defined/imported
        self.current_path = self.path_root
        super().generic_visit(
            node
        )  # Call generic_visit from ast.NodeVisitor via TaintVisitor
        if self.debug:
            debug(
                f"\n========== Finished analysis of file: {self.file_path} =========="
            )
            debug(f"Found {len(self.found_sinks)} sinks")
            debug(f"Found {len(self.found_sources)} sources")

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
                        "value_type": type(
                            node.value
                        ).__name__,  # Store type of assigned value
                    }
                    # If the value is a call to a source function
                    if isinstance(node.value, ast.Call):
                        func_name, full_name = self._get_func_name_with_module(
                            node.value.func
                        )
                        if self._is_source(
                            func_name, full_name
                        ):  # _is_source needs to be defined
                            if self.debug:
                                debug(
                                    f"Found source assignment: {var_name} = {func_name}() at line {node.lineno}"
                                )
                            source_type = self._get_source_type(
                                func_name, full_name
                            )  # _get_source_type needs to be defined
                            source_info = {
                                "name": source_type,
                                "line": node.lineno,
                                "col": node.col_offset,
                                # "node": node, # Storing AST nodes directly can be memory intensive
                                "statement": self._get_node_source(node),
                            }
                            self.source_statements[var_name] = source_info
                            self.tainted[
                                var_name
                            ] = source_info  # self.tainted is from TaintVisitor
                            self.found_sources.append(
                                source_info
                            )  # Add to found_sources
        super().visit_Assign(
            node
        )  # Call parent's visit_Assign for its logic (e.g., taint propagation)

    def _get_node_source(self, node: ast.AST) -> str:
        """Get the source code for a node."""
        # ast.unparse can be more robust if available (Python 3.9+)
        if hasattr(ast, "unparse"):
            try:
                return ast.unparse(node)
            except Exception:  # Fallback if unparse fails for some nodes
                pass

        # Fallback to line-based extraction
        if (
            hasattr(node, "lineno")
            and hasattr(node, "end_lineno")
            and hasattr(node, "col_offset")
            and hasattr(node, "end_col_offset")
            and self.source_lines
        ):
            start_line = node.lineno - 1
            end_line = node.end_lineno - 1
            if 0 <= start_line < len(self.source_lines) and 0 <= end_line < len(
                self.source_lines
            ):
                if start_line == end_line:
                    return self.source_lines[start_line][
                        node.col_offset : node.end_col_offset
                    ].strip()
                else:
                    lines = [
                        self.source_lines[start_line][node.col_offset :].rstrip("\r\n")
                    ]
                    for i in range(start_line + 1, end_line):
                        lines.append(self.source_lines[i].rstrip("\r\n"))
                    lines.append(
                        self.source_lines[end_line][: node.end_col_offset].strip()
                    )
                    return "\n".join(lines)
        return "Source not available"

    def visit_Call(self, node: ast.Call) -> None:
        """
        Enhanced visit_Call to better track data flow and source propagation.
        Also handles function call graph construction and self.method() calls.
        """
        # Log debug information
        current_func_display_name = getattr(
            self.current_function, "name", "GlobalScope"
        )
        debug(
            f"[FORCE] Enter visit_Call: in function {current_func_display_name}, call to '{ast.unparse(node.func) if hasattr(ast, 'unparse') else 'function'}' at line {getattr(node, 'lineno', 'N/A')}"
        )

        func_name, full_name = self._get_func_name_with_module(node.func)
        line_no = getattr(node, "lineno", 0)

        # Original EnhancedTaintVisitor.visit_Call functionality - data flow analysis (simplified portion)
        # This part seems to be specific handling for 'recv' and method calls on tainted vars
        if func_name and (
            "recv" in func_name or (full_name and "recv" in full_name)
        ):  # Check both simple and full name
            if self.debug:
                debug(
                    f"Detected potential recv function: {func_name} (full: {full_name}) at line {line_no}"
                )
            parent = self.parent_map.get(node)  # self.parent_map from TaintVisitor
            if parent and isinstance(parent, ast.Assign):
                for target in parent.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        if self.debug:
                            debug(
                                f"  Return value of '{func_name}' assigned to: {var_name}"
                            )
                        if self._is_source(func_name, full_name):
                            source_type = self._get_source_type(func_name, full_name)
                            source_info: Dict[str, Any] = {  # Explicit typing
                                "name": source_type,
                                "line": line_no,
                                "col": node.col_offset,
                                # "node": node, # Avoid storing nodes directly
                                "statement": self._get_node_source(node),
                            }
                            self.tainted[var_name] = source_info
                            self.source_statements[var_name] = source_info
                            self.found_sources.append(source_info)
                            if self.debug:
                                debug(
                                    f"  Marked '{var_name}' as tainted from source '{source_type}' via '{func_name}'"
                                )

        # Taint propagation for method calls on tainted objects
        if isinstance(node.func, ast.Attribute) and isinstance(
            node.func.value, ast.Name
        ):
            obj_name = node.func.value.id  # Name of the object
            method_name_str = node.func.attr  # Name of the method
            if obj_name in self.tainted:
                # More specific keys like "str.join", "list.append" are handled by _initialize_operation_taint_rules
                # This is a general propagation for method calls on any tainted object if not covered by specific rules.
                if self.debug:
                    debug(
                        f"Tracking method call '{method_name_str}' on tainted variable: '{obj_name}' at line {line_no}"
                    )
                parent = self.parent_map.get(node)
                if parent and isinstance(parent, ast.Assign):
                    for target in parent.targets:
                        if isinstance(target, ast.Name):
                            new_var = target.id
                            # Basic propagation: if object is tainted, method result is tainted
                            # More sophisticated rules can be applied from self.operation_taint_rules
                            self.tainted[new_var] = self.tainted[
                                obj_name
                            ]  # Propagate original source info
                            if self.debug:
                                debug(
                                    f"  Taint from '{obj_name}' propagated via method '{method_name_str}' to: '{new_var}'"
                                )

        # Functionality integrated from FunctionVisitorMixin.visit_Call - call graph construction
        if self.debug:
            debug(
                f"Call graph processing for: {func_name} (full: {full_name}) at line {getattr(node, 'lineno', 0)}"
            )

        # Add call graph construction logic
        if (
            self.current_function and func_name and func_name in self.functions
        ):  # Check func_name exists
            callee_node = self.functions[func_name]
            self.current_function.add_callee(callee_node)  # type: ignore # current_function is CallGraphNode
            callee_node.add_caller(self.current_function)

            # Record call line number to build a more complete call chain
            call_line = getattr(node, "lineno", 0)
            # callee_node.call_line = call_line # This would overwrite; call_points is better

            # Get call statement
            call_statement = self._get_call_source_code(
                node
            )  # Pass node for better source extraction

            # Add detailed call point information
            callee_node.add_call_point(call_line, call_statement, self.current_function.name)  # type: ignore

            # Check if it is a self.method() call
            if isinstance(node.func, ast.Attribute) and isinstance(
                node.func.value, ast.Name
            ):
                if node.func.value.id == "self":
                    # Record this as a self method call
                    callee_node.is_self_method_call = True
                    callee_node.self_method_name = node.func.attr
                    if not hasattr(self, "self_method_call_map"):
                        self.self_method_call_map = {}
                    map_key = f"{self.current_function.name} -> self.{node.func.attr}"  # type: ignore
                    self.self_method_call_map.setdefault(map_key, []).append(call_line)

                    if hasattr(self.current_function, "self_method_calls") and isinstance(self.current_function.self_method_calls, list):  # type: ignore
                        self.current_function.self_method_calls.append(  # type: ignore
                            {
                                "method": node.func.attr,
                                "line": call_line,
                                "call_statement": call_statement,
                            }
                        )
                    if self.debug:
                        debug(
                            f"  -> Recorded self.{node.func.attr}() call at line {call_line} in {self.current_function.name}"  # type: ignore
                        )
                    # Assuming self.callgraph exists and has this method from an imported module
                    if hasattr(self, "callgraph") and hasattr(
                        self.callgraph, "add_self_method_call"
                    ):
                        self.callgraph.add_self_method_call(  # type: ignore
                            self.current_function.name, node.func.attr, call_line  # type: ignore
                        )

            # Track parameter taint propagation
            if hasattr(
                self, "_track_parameter_taint_propagation"
            ):  # Check if mixin method is available
                self._track_parameter_taint_propagation(node, func_name)  # type: ignore
        elif self.debug and func_name:  # Added check for func_name
            debug(
                f"  -> Call to external/undefined function '{func_name}' or no current function context. Ignored for call graph."
            )

        # Return value taint propagation
        if (
            hasattr(self, "_track_return_taint_propagation") and func_name
        ):  # Check if mixin method is available
            self._track_return_taint_propagation(node, func_name)  # type: ignore

        # Data structure operation tracking
        if (
            hasattr(self, "_track_data_structure_operations") and func_name
        ):  # Check if mixin method is available
            self._track_data_structure_operations(node, func_name, full_name)  # type: ignore

        # Container method tracking
        if hasattr(
            self, "_track_container_methods"
        ):  # Check if mixin method is available
            self._track_container_methods(node)  # type: ignore

        # Call parent class's visit_Call method to ensure sink detection logic is executed
        super().visit_Call(node)

    # Add helper method to extract source code at a specific call location
    def _get_call_source_code(self, node_or_line_no: Union[ast.AST, int]) -> str:  # type: ignore
        """Get the source code for a specific AST node or line number."""
        if isinstance(node_or_line_no, ast.AST):
            return self._get_node_source(node_or_line_no)
        elif isinstance(node_or_line_no, int):
            line_no = node_or_line_no
            if (
                hasattr(self, "source_lines")
                and self.source_lines
                and 0 < line_no <= len(self.source_lines)
            ):
                return self.source_lines[line_no - 1].strip()
        return "Source line not available"

    def _track_assignment_taint(
        self, node: ast.Call, source_info: Dict[str, Any]
    ) -> None:
        """
        Enhanced assignment taint tracking to ensure all assignments from call results are tracked.
        This method assumes `node` is the ast.Call node whose result might be assigned.
        """
        # Call the original _track_assignment_taint from TaintVisitor first
        super()._track_assignment_taint(node, source_info)

        # Additional tracking for complex assignments (e.g., chained calls, attribute assignments)
        # The logic here tries to find if the result of 'node' (the Call) is ultimately assigned.
        # This requires careful traversal up the parent_map.

        current_node_in_chain = node
        parent_of_current = self.parent_map.get(current_node_in_chain)

        while parent_of_current is not None:
            if isinstance(parent_of_current, ast.Assign):
                # The result of the call chain ending in 'current_node_in_chain' is assigned.
                for target_node in parent_of_current.targets:
                    if isinstance(target_node, ast.Name):
                        var_name = target_node.id
                        if (
                            var_name not in self.tainted
                            or self.tainted[var_name] != source_info
                        ):  # Avoid redundant logging if already tainted by super call
                            self.tainted[var_name] = source_info
                            if self.debug:
                                debug(
                                    f"Tracked taint (EnhancedTaintVisitor) to variable '{var_name}' from call result."
                                )
                    # TODO: Handle attribute assignments (e.g., self.x = call()) or subscript assignments (e.g., d['key'] = call())
                break  # Found the assignment, stop traversing up

            # If the parent is part of a call chain (e.g., call().method()), continue up.
            # If it's something else (e.g., an argument to another call), the direct assignment is not to a variable.
            if not (
                isinstance(parent_of_current, ast.Attribute)
                or isinstance(parent_of_current, ast.Call)
                or isinstance(parent_of_current, ast.Subscript)
            ):
                break

            current_node_in_chain = parent_of_current
            parent_of_current = self.parent_map.get(current_node_in_chain)

        # Taint propagation to function return if current_function is active
        if self.current_function and self.current_function.ast_node:  # type: ignore # current_function is CallGraphNode
            for ast_walk_node in ast.walk(self.current_function.ast_node):  # type: ignore
                if isinstance(ast_walk_node, ast.Return) and ast_walk_node.value:
                    # This logic checks if any variable *currently* marked as tainted is returned.
                    # It might be better to check if the specific 'source_info' from this call
                    # is what's being returned, which requires more complex data flow.
                    # The current check is broader: if ANY tainted var is returned.
                    # This simplified part might be from the original snippet logic.
                    if isinstance(ast_walk_node.value, ast.Name):
                        returned_var_name = ast_walk_node.value.id
                        if (
                            returned_var_name in self.tainted
                        ):  # Check if the returned var is tainted
                            # If the source_info of the returned var matches the current call's source_info, it's a direct propagation
                            if self.tainted[returned_var_name] == source_info:
                                self.current_function.return_tainted = True  # type: ignore
                                if source_info not in self.current_function.return_taint_sources:  # type: ignore
                                    self.current_function.return_taint_sources.append(source_info)  # type: ignore
                                if self.debug:
                                    debug(
                                        f"Function {self.current_function.name} now returns tainted value due to return of '{returned_var_name}' (from current call)."  # type: ignore
                                    )

    def _get_func_name_with_module(self, node: ast.AST) -> Tuple[str, Optional[str]]:
        """Enhanced version of _get_func_name_with_module to handle more cases,
        including resolving aliased imports."""
        func_name, full_name = super()._get_func_name_with_module(node)  # type: ignore # Call base method

        # If full_name is not resolved by superclass (e.g., it's a direct name like 'my_func' or 'aliased_open')
        # and it's an alias from an import, try to resolve it.
        if not full_name and func_name in self.module_imports:
            module_path, original_func_name = self.module_imports[func_name]
            if module_path:  # If it's from a module (e.g., from x import y as z)
                full_name = f"{module_path}.{original_func_name}"
            else:  # If it's a top-level import alias (e.g., import x as y) and func_name is 'y'
                # this case might be more complex if 'original_func_name' is a module itself.
                # For now, assume 'original_name' is the actual function name if module_path is empty.
                full_name = original_func_name

        # Handle cases like `module.submodule.function` where func_name from super might just be `function`
        # and full_name might be `module.submodule.function`. This part is usually handled by super().
        # This enhancement focuses on aliases.

        return func_name, full_name
