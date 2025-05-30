import ast
import re
import os
from typing import Any, Dict, Optional, Tuple
from lanalyzer.logger import get_logger

logger = get_logger("lanalyzer.analysis.ast_parser")


class ParentNodeVisitor(ast.NodeVisitor):
    """
    AST visitor that adds parent references to nodes.
    """

    def __init__(self):
        self.parent_map = {}

    def visit(self, node):
        for child in ast.iter_child_nodes(node):
            self.parent_map[child] = node
        super().visit(node)


class TaintVisitor(ast.NodeVisitor):
    def __init__(
        self,
        parent_map=None,
        debug_mode: bool = False,
        verbose: bool = False,
        file_path: Optional[str] = None,
    ):
        """
        Initialize the taint visitor.

        Args:
            parent_map: Dictionary mapping AST nodes to their parents
            debug_mode: Whether to enable debug output
            verbose: Whether to enable verbose output
            file_path: Path to the file being analyzed
        """
        self.parent_map = parent_map or {}
        self.found_sources = []
        self.found_sinks = []
        self.found_vulnerabilities = []
        self.tainted = {}
        self.debug = debug_mode
        self.verbose = verbose
        self.file_path = file_path
        self.source_lines = None

        if file_path and os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    self.source_lines = f.readlines()
                if self.debug:
                    logger.debug(
                        f"Loaded {len(self.source_lines)} lines of source code from {file_path}"
                    )
            except Exception as e:
                if self.debug:
                    logger.debug(f"Failed to load source code: {str(e)}")

        self.import_aliases = {}
        self.from_imports = {}
        self.direct_imports = set()

    def visit_Import(self, node: ast.Import) -> None:
        """
        Visit an import node to track aliases.
        """
        for name in node.names:
            if self.debug:
                logger.debug(
                    f"\n[Import Tracking] Processing import: {name.name}"
                    + (f" as {name.asname}" if name.asname else "")
                )

            if name.asname:
                self.import_aliases[name.asname] = name.name
                if self.debug:
                    logger.debug(f"  Recording alias: {name.asname} -> {name.name}")
            else:
                self.direct_imports.add(name.name)
                self.from_imports[name.name] = name.name
                if self.debug:
                    logger.debug(f"  Recording direct import: {name.name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """
        Visit a from-import node to track imported names.
        """
        if node.module:
            for name in node.names:
                imported_name = name.name
                full_name = f"{node.module}.{imported_name}"
                if name.asname:
                    self.from_imports[name.asname] = full_name
                    if self.debug:
                        logger.debug(
                            f"Tracked from-import with alias: {name.asname} -> {full_name}"
                        )
                else:
                    self.from_imports[imported_name] = full_name
                    if self.debug:
                        logger.debug(
                            f"Tracked from-import: {imported_name} -> {full_name}"
                        )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """
        Visit a function call node in the AST.

        Args:
            node: AST node representing a function call
        """
        func_name, full_name = self._get_func_name_with_module(node.func)
        self.full_func_name = full_name

        line_no = getattr(node, "lineno", 0)
        col_offset = getattr(node, "col_offset", 0)

        if self.debug:
            logger.debug(
                f"Visiting call: {func_name} (full: {full_name}) at line {line_no}"
            )
            args_str = ", ".join([ast.dump(arg) for arg in node.args])
            if args_str:
                logger.debug(f"  Args: {args_str}")
            if node.keywords:
                keywords_str = ", ".join(
                    [f"{kw.arg}={ast.dump(kw.value)}" for kw in node.keywords]
                )
                logger.debug(f"  Keywords: {keywords_str}")

        if func_name and self._is_source(func_name, full_name):
            source_type = self._get_source_type(func_name, full_name)

            source_info = {
                "name": source_type,
                "line": line_no,
                "col": col_offset,
                "node": node,
            }

            self.found_sources.append(source_info)

            if self.debug:
                logger.debug(f"Found source: {source_type} at line {line_no}")

            self._track_assignment_taint(node, source_info)

        if func_name and self._is_sink(func_name, full_name):
            sink_type = self._get_sink_type(func_name, full_name)
            vulnerability_type = self._get_sink_vulnerability_type(sink_type)

            sink_info = {
                "name": sink_type,
                "line": line_no,
                "col": col_offset,
                "node": node,
                "vulnerability_type": vulnerability_type,
            }

            self.found_sinks.append(sink_info)
            self._check_sink_args(node, sink_type, sink_info)

        if func_name in ["eval", "exec", "execfile"]:
            if node.args:
                arg = node.args[0]
                arg_name = None

                if isinstance(arg, ast.Name):
                    arg_name = arg.id
                elif isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute):
                    if isinstance(arg.func.value, ast.Name):
                        arg_name = f"{arg.func.value.id}.{arg.func.attr}()"

                if arg_name and arg_name in self.tainted:
                    source_info = self.tainted[arg_name]

                    sink_info = None
                    for sink in self.found_sinks:
                        if sink["line"] == line_no and sink["name"] == "CodeExecution":
                            sink_info = sink
                            break

                    if not sink_info:
                        sink_info = {
                            "name": "CodeExecution",
                            "line": line_no,
                            "col": col_offset,
                            "tainted_args": [],
                        }
                        self.found_sinks.append(sink_info)
                    else:
                        if "tainted_args" not in sink_info:
                            sink_info["tainted_args"] = []

                    sink_info["tainted_args"].append((arg_name, source_info))

                    if self.debug:
                        logger.debug(
                            f"Found tainted argument {arg_name} from {source_info['name']} in {func_name} call"
                        )

        self.generic_visit(node)

    def _print_function_args(self, node: ast.Call) -> None:
        """
        Print the function arguments for debugging.

        Args:
            node: AST node representing a function call
        """
        args = []
        for arg in node.args:
            if isinstance(arg, ast.Name):
                args.append(f"Name({arg.id})")
            elif isinstance(arg, ast.Constant):
                args.append(f"Constant({repr(arg.value)})")
            elif isinstance(arg, ast.Call):
                func_name, _ = self._get_func_name_with_module(arg.func)
                args.append(f"Call({func_name})")
            else:
                args.append(f"{type(arg).__name__}")

        kws = []
        for kw in node.keywords:
            if isinstance(kw.value, ast.Name):
                kws.append(f"{kw.arg}=Name({kw.value.id})")
            elif isinstance(kw.value, ast.Constant):
                kws.append(f"{kw.arg}=Constant({repr(kw.value.value)})")
            else:
                kws.append(f"{kw.arg}={type(kw.value).__name__}")

        logger.debug(f"  Args: {', '.join(args)}")
        if kws:
            logger.debug(f"  Keywords: {', '.join(kws)}")

    def visit_Assign(self, node):
        """Visit an assignment node and track taint propagation.

        Args:
            node: AST node representing an assignment
        """
        if isinstance(node.value, ast.Call):
            func_name, full_name = self._get_func_name_with_module(node.value.func)

            if self.debug:
                logger.debug(
                    f"Checking assignment with function call: {func_name} (full: {full_name}) at line {getattr(node, 'lineno', 0)}"
                )

            if func_name and self._is_source(func_name, full_name):
                source_type = self._get_source_type(func_name, full_name)
                line_no = getattr(node.value, "lineno", 0)
                col_offset = getattr(node.value, "col_offset", 0)

                source_info = {
                    "name": source_type,
                    "line": line_no,
                    "col": col_offset,
                    "node": node.value,
                }

                self.found_sources.append(source_info)

                if self.debug:
                    logger.debug(
                        f"Found source in assignment: {source_type} at line {line_no}"
                    )

                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted[target.id] = source_info
                        if self.debug:
                            logger.debug(
                                f"Tainted variable '{target.id}' from source {source_type}"
                            )

            elif func_name == "input":
                line_no = getattr(node.value, "lineno", 0)
                col_offset = getattr(node.value, "col_offset", 0)

                source_info = {
                    "name": "UserInput",
                    "line": line_no,
                    "col": col_offset,
                    "node": node.value,
                }

                self.found_sources.append(source_info)

                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted[target.id] = source_info
                        if self.debug:
                            logger.debug(
                                f"Tainted variable '{target.id}' from UserInput at line {line_no}"
                            )

            elif func_name == "getenv" and full_name == "os.getenv":
                line_no = getattr(node.value, "lineno", 0)
                col_offset = getattr(node.value, "col_offset", 0)

                source_info = {
                    "name": "EnvironmentVariables",
                    "line": line_no,
                    "col": col_offset,
                    "node": node.value,
                }

                self.found_sources.append(source_info)

                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted[target.id] = source_info
                        if self.debug:
                            logger.debug(
                                f"Tainted variable '{target.id}' from EnvironmentVariables at line {line_no}"
                            )

            elif func_name == "read" and isinstance(node.value.func, ast.Attribute):
                line_no = getattr(node.value, "lineno", 0)
                col_offset = getattr(node.value, "col_offset", 0)

                source_info = {
                    "name": "FileRead",
                    "line": line_no,
                    "col": col_offset,
                    "node": node.value,
                }

                self.found_sources.append(source_info)

                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted[target.id] = source_info
                        if self.debug:
                            logger.debug(
                                f"Tainted variable '{target.id}' from FileRead at line {line_no}"
                            )

        elif isinstance(node.value, ast.Name) and node.value.id in self.tainted:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted[target.id] = self.tainted[node.value.id]
                    if self.debug:
                        logger.debug(
                            f"Propagated taint from {node.value.id} to {target.id} at line {getattr(node, 'lineno', 0)}"
                        )

        elif isinstance(node.value, ast.Attribute) and isinstance(
            node.value.value, ast.Name
        ):
            if node.value.value.id in self.tainted:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted[target.id] = self.tainted[node.value.value.id]
                        if self.debug:
                            logger.debug(
                                f"Propagated taint from {node.value.value.id}.{node.value.attr} to {target.id} at line {getattr(node, 'lineno', 0)}"
                            )

        elif isinstance(node.value, ast.Subscript) and isinstance(
            node.value.value, ast.Name
        ):
            if node.value.value.id in self.tainted:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted[target.id] = self.tainted[node.value.value.id]
                        if self.debug:
                            logger.debug(
                                f"Propagated taint from {node.value.value.id}[...] to {target.id} at line {getattr(node, 'lineno', 0)}"
                            )

        elif (
            isinstance(node.value, ast.Subscript)
            and isinstance(node.value.value, ast.Attribute)
            and node.value.value.attr == "argv"
            and isinstance(node.value.value.value, ast.Name)
            and node.value.value.value.id == "sys"
        ):
            line_no = getattr(node.value, "lineno", 0)
            col_offset = getattr(node.value, "col_offset", 0)

            source_info = {
                "name": "CommandLineArgs",
                "line": line_no,
                "col": col_offset,
                "node": node.value,
            }

            self.found_sources.append(source_info)

            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted[target.id] = source_info
                    if self.debug:
                        logger.debug(
                            f"Tainted variable '{target.id}' from CommandLineArgs at line {line_no}"
                        )

        self.generic_visit(node)

    def _get_func_name_with_module(
        self, func: ast.expr
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Get the name of a function from its AST node, considering imports and aliases.

        Args:
            func: AST node representing a function

        Returns:
            Tuple of (simple function name, full function name with module) or (None, None)
        """
        if self.debug:
            logger.debug(
                f"\n[Function Name Parsing] Starting parsing: {ast.dump(func)}"
            )

        if func is None:
            if self.debug:
                logger.debug("  Function node is None")
            return None, None

        if isinstance(func, ast.Name):
            simple_name = func.id

            if simple_name in self.from_imports:
                full_name = self.from_imports[simple_name]
                if self.debug:
                    logger.debug(
                        f"  Found mapping in from_imports: {simple_name} -> {full_name}"
                    )
                return simple_name, full_name

            if simple_name in self.import_aliases:
                module_name = self.import_aliases[simple_name]
                if self.debug:
                    logger.debug(
                        f"  Found mapping in import_aliases: {simple_name} -> {module_name}"
                    )
                return simple_name, module_name

            if simple_name in self.direct_imports:
                if self.debug:
                    logger.debug(f"  Found in direct_imports: {simple_name}")
                return simple_name, simple_name

            if self.debug:
                logger.debug(f"  Using simple name: {simple_name}")
            return simple_name, simple_name

        elif isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                module_name = func.value.id
                attr_name = func.attr

                if module_name in self.import_aliases:
                    real_module = self.import_aliases[module_name]
                    full_name = f"{real_module}.{attr_name}"
                    if self.debug:
                        logger.debug(
                            f"  Parsed from module alias: {module_name}.{attr_name} -> {full_name}"
                        )
                else:
                    full_name = f"{module_name}.{attr_name}"
                    if self.debug:
                        logger.debug(f"  Constructed full name: {full_name}")

                return attr_name, full_name

            elif isinstance(func.value, ast.Attribute):
                _, parent_full = self._get_func_name_with_module(func.value)
                if parent_full:
                    full_name = f"{parent_full}.{func.attr}"
                    if self.debug:
                        logger.debug(f"  Handling nested attributes: {full_name}")
                    return func.attr, full_name

        try:
            expr_str = ast.unparse(func)
            if self.debug:
                logger.debug(f"  Complex expression: {expr_str}")
            return expr_str, None
        except (AttributeError, ValueError):
            pass

        if self.debug:
            logger.debug("  Unable to parse function name")
        return None, None

    def _is_source(self, func_name: str, full_name: Optional[str] = None) -> bool:
        """
        Check if a function name is a source.

        Args:
            func_name: Simple name of the function
            full_name: Full name of the function with module

        Returns:
            True if the function is a source, False otherwise
        """
        if not isinstance(func_name, str):
            if self.debug:
                logger.warning(f"func_name is not a string: {type(func_name)}")
            return False

        if full_name is not None and not isinstance(full_name, str):
            if self.debug:
                logger.warning(f"full_name is not a string: {type(full_name)}")
            full_name = None

        for source in self.sources:
            for pattern in source["patterns"]:
                if pattern == func_name:
                    return True

                if full_name and pattern in full_name:
                    return True

                if "*" in pattern:
                    regex_pattern = pattern.replace(".", "\\.").replace("*", ".*")
                    if re.match(regex_pattern, func_name) or (
                        full_name and re.match(regex_pattern, full_name)
                    ):
                        return True

        return False

    def _get_source_type(self, func_name: str, full_name: Optional[str] = None) -> str:
        """
        Get the type of a source function.

        Args:
            func_name: Simple name of the function
            full_name: Full name of the function with module

        Returns:
            Type of the source
        """
        if not isinstance(func_name, str):
            if self.debug:
                logger.warning(
                    f"func_name is not a string in _get_source_type: {type(func_name)}"
                )
            return "Unknown"

        if full_name is not None and not isinstance(full_name, str):
            if self.debug:
                logger.warning(
                    f"full_name is not a string in _get_source_type: {type(full_name)}"
                )
            full_name = None

        for source in self.sources:
            for pattern in source["patterns"]:
                if pattern == func_name or (full_name and pattern in full_name):
                    return source["name"]

                if "*" in pattern:
                    regex_pattern = pattern.replace(".", "\\.").replace("*", ".*")
                    if re.match(regex_pattern, func_name) or (
                        full_name and re.match(regex_pattern, full_name)
                    ):
                        return source["name"]

        return "Unknown"

    def _is_sink(self, func_name: str, full_name: Optional[str] = None) -> bool:
        """
        Check if a function name is a sink based on configuration patterns.
        """
        if not isinstance(func_name, str):
            if self.debug:
                logger.warning(
                    f"func_name is not a string in _is_sink: {type(func_name)}"
                )
            return False

        if full_name is not None and not isinstance(full_name, str):
            if self.debug:
                logger.warning(
                    f"full_name is not a string in _is_sink: {type(full_name)}"
                )
            full_name = None

        if self.debug:
            logger.debug(
                f"\n[Sink Check] Checking function: {func_name} (full name: {full_name or 'N/A'})"
            )
            logger.debug("  Current import information:")
            logger.debug(f"    - Direct imports: {self.direct_imports}")
            logger.debug(f"    - Alias imports: {self.import_aliases}")
            logger.debug(f"    - From imports: {self.from_imports}")

        for sink in self.sinks:
            sink_name = sink.get("name", "Unknown")
            if self.debug:
                logger.debug(f"  [Sink Type] Checking patterns for {sink_name}:")

            for pattern in sink["patterns"]:
                if self.debug:
                    logger.debug(f"    - Current pattern: {pattern}")
                    logger.debug(
                        f"      Comparing: function name='{func_name}', full name='{full_name}'"
                    )

                if pattern == func_name:
                    if self.debug:
                        logger.debug(
                            f"    ✓ Match found: simple name match - {pattern}"
                        )
                    return True

                if full_name:
                    if pattern == full_name:
                        if self.debug:
                            logger.debug(
                                f"    ✓ Match successful: Exact full name match - {pattern}"
                            )
                        return True
                    if pattern in full_name:
                        if self.debug:
                            logger.debug(
                                f"    ✓ Match successful: Full name contains pattern - {pattern} in {full_name}"
                            )
                        return True

                if "*" in pattern:
                    regex_pattern = pattern.replace(".", "\\.").replace("*", ".*")
                    if re.match(regex_pattern, func_name):
                        if self.debug:
                            logger.debug(
                                f"    ✓ Match successful: Function name wildcard match - {pattern}"
                            )
                        return True
                    if full_name and re.match(regex_pattern, full_name):
                        if self.debug:
                            logger.debug(
                                f"    ✓ Match successful: Full name wildcard match - {pattern}"
                            )
                        return True

                if self.debug:
                    logger.debug("    × No match for this pattern")

        if self.debug:
            logger.debug(f"[Sink check result] {func_name}: Not a sink\n")
        return False

    def _get_sink_type(self, func_name: str, full_name: Optional[str] = None) -> str:
        """
        Get the type of a sink function based on configuration.

        Args:
            func_name: Simple name of the function
            full_name: Full name of the function with module

        Returns:
            Type of the sink
        """
        if not isinstance(func_name, str):
            if self.debug:
                logger.warning(
                    f"func_name is not a string in _get_sink_type: {type(func_name)}"
                )
            return "Unknown"

        if full_name is not None and not isinstance(full_name, str):
            if self.debug:
                logger.warning(
                    f"full_name is not a string in _get_sink_type: {type(full_name)}"
                )
            full_name = None

        for sink in self.sinks:
            for pattern in sink["patterns"]:
                if pattern == func_name or (full_name and pattern in full_name):
                    return sink["name"]

                if "*" in pattern:
                    regex_pattern = pattern.replace(".", "\\.").replace("*", ".*")
                    if re.match(regex_pattern, func_name) or (
                        full_name and re.match(regex_pattern, full_name)
                    ):
                        return sink["name"]

        return "Unknown"

    def _track_assignment_taint(
        self, node: ast.Call, source_info: Dict[str, Any]
    ) -> None:
        """
        Track taint for variables assigned from sources.

        Args:
            node: AST node representing a function call
            source_info: Information about the source
        """
        if hasattr(node, "parent"):
            parent = node.parent

            if isinstance(parent, ast.Assign):
                for target in parent.targets:
                    if isinstance(target, ast.Name):
                        self.tainted[target.id] = source_info
                        if self.debug:
                            logger.debug(
                                f"Tainted variable '{target.id}' from direct assignment at line {getattr(parent, 'lineno', 0)}"
                            )

            elif isinstance(parent, ast.AugAssign) and isinstance(
                parent.target, ast.Name
            ):
                self.tainted[parent.target.id] = source_info
                if self.debug:
                    logger.debug(
                        f"Tainted variable '{parent.target.id}' from augmented assignment at line {getattr(parent, 'lineno', 0)}"
                    )

            elif isinstance(parent, ast.For) and node == parent.iter:
                if isinstance(parent.target, ast.Name):
                    self.tainted[parent.target.id] = source_info
                    if self.debug:
                        logger.debug(
                            f"Tainted variable '{parent.target.id}' from for loop at line {getattr(parent, 'lineno', 0)}"
                        )
                elif isinstance(parent.target, ast.Tuple):
                    for elt in parent.target.elts:
                        if isinstance(elt, ast.Name):
                            self.tainted[elt.id] = source_info
                            if self.debug:
                                logger.debug(
                                    f"Tainted variable '{elt.id}' from for loop tuple unpacking at line {getattr(parent, 'lineno', 0)}"
                                )

    def _check_sink_args(
        self, node: ast.Call, sink_type: str, sink_info: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Check if any arguments to a sink function are tainted.

        Args:
            node: AST node representing a function call
            sink_type: Type of the sink
            sink_info: Information about the sink (optional)
        """
        tainted_args = []

        func_name, full_name = self._get_func_name_with_module(node.func)
        if func_name == "open" and len(node.args) >= 1:
            if (
                hasattr(node, "parent")
                and isinstance(node.parent, ast.Assign)
                and len(node.parent.targets) == 1
            ):
                if isinstance(node.parent.targets[0], ast.Name):
                    file_handle_name = node.parent.targets[0].id

                    path_arg = node.args[0]
                    if isinstance(path_arg, ast.Name) and path_arg.id in self.tainted:
                        if not hasattr(self, "file_handles"):
                            self.file_handles = {}

                        self.file_handles[file_handle_name] = {
                            "source_var": path_arg.id,
                            "source_info": self.tainted[path_arg.id],
                        }

                        if self.debug:
                            logger.debug(
                                f"Tracking file handle '{file_handle_name}' from tainted path '{path_arg.id}'"
                            )

        for i, arg in enumerate(node.args):
            tainted = False
            source_info = None
            arg_name = None

            if isinstance(arg, ast.Name):
                arg_name = arg.id
                if arg_name in self.tainted:
                    source_info = self.tainted[arg_name]
                    tainted = True
                elif hasattr(self, "file_handles") and arg_name in self.file_handles:
                    file_info = self.file_handles[arg_name]
                    source_info = file_info["source_info"]
                    tainted = True
                    arg_name = f"{arg_name}(from {file_info['source_var']})"

                    if self.debug:
                        logger.debug(
                            f"Found tainted file handle '{arg_name}' passed to sink"
                        )

            elif (
                isinstance(arg, ast.Call)
                and isinstance(arg.func, ast.Attribute)
                and isinstance(arg.func.value, ast.Name)
            ):
                base_var = arg.func.value.id
                if base_var in self.tainted:
                    source_info = self.tainted[base_var]
                    tainted = True
                    method_name = arg.func.attr
                    arg_name = f"{base_var}.{method_name}()"

                    if self.debug:
                        logger.debug(
                            f"Found tainted method call '{arg_name}' from tainted variable '{base_var}'"
                        )

            elif isinstance(arg, ast.Call):
                sub_func_name, sub_full_name = self._get_func_name_with_module(arg.func)
                if sub_func_name == "open":
                    source_info = {
                        "name": "FileRead",
                        "line": getattr(arg, "lineno", 0),
                        "col": getattr(arg, "col_offset", 0),
                    }
                    tainted = True
                    arg_name = f"direct_call_{i}"

            elif (
                isinstance(arg, ast.Name)
                and arg.id in self.file_handles
                and self.file_handles[arg.id].get("from_with")
            ):
                file_info = self.file_handles[arg.id]
                source_info = file_info["source_info"]
                tainted = True
                arg_name = f"{arg.id}(from {file_info['source_var']} in with)"

                if self.debug:
                    logger.debug(
                        f"Found tainted file handle '{arg_name}' from with-statement passed to sink"
                    )

            if tainted and source_info:
                tainted_args.append((arg_name, source_info))
                if self.debug:
                    logger.debug(
                        f"Found tainted argument '{arg_name}' (position {i}) to sink '{sink_type}' at line {getattr(node, 'lineno', 0)}"
                    )

        for i, kw in enumerate(node.keywords):
            tainted = False
            source_info = None
            arg_name = None

            if isinstance(kw.value, ast.Name):
                arg_name = f"{kw.arg}={kw.value.id}"
                if kw.value.id in self.tainted:
                    source_info = self.tainted[kw.value.id]
                    tainted = True
                elif hasattr(self, "file_handles") and kw.value.id in self.file_handles:
                    file_info = self.file_handles[kw.value.id]
                    source_info = file_info["source_info"]
                    tainted = True
                    arg_name = f"{kw.arg}={kw.value.id}(from {file_info['source_var']})"

            elif (
                isinstance(kw.value, ast.Call)
                and isinstance(kw.value.func, ast.Attribute)
                and isinstance(kw.value.func.value, ast.Name)
            ):
                base_var = kw.value.func.value.id
                if base_var in self.tainted:
                    source_info = self.tainted[base_var]
                    tainted = True
                    method_name = kw.value.func.attr
                    arg_name = f"{kw.arg}={base_var}.{method_name}()"

            elif isinstance(kw.value, ast.Call):
                sub_func_name, sub_full_name = self._get_func_name_with_module(
                    kw.value.func
                )
                if sub_func_name and self._is_source(sub_func_name, sub_full_name):
                    source_type = self._get_source_type(sub_func_name, sub_full_name)
                    source_info = {
                        "name": source_type,
                        "line": getattr(kw.value, "lineno", 0),
                        "col": getattr(kw.value, "col_offset", 0),
                    }
                    tainted = True
                    arg_name = f"{kw.arg}=direct_call"

            if tainted and source_info:
                tainted_args.append((arg_name, source_info))
                if self.debug:
                    logger.debug(
                        f"Found tainted keyword argument '{arg_name}' to sink '{sink_type}' at line {getattr(node, 'lineno', 0)}"
                    )

        if tainted_args and sink_info is not None:
            sink_info["tainted_args"] = tainted_args
            if self.debug:
                logger.debug(
                    f"Added {len(tainted_args)} tainted args to sink info at line {getattr(node, 'lineno', 0)}"
                )

        if not tainted_args and self.debug:
            logger.debug(
                f"No tainted arguments found for sink '{sink_type}' at line {getattr(node, 'lineno', 0)}"
            )
            arg_names = []
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    arg_names.append(arg.id)
            logger.debug(f"  Arguments: {', '.join(arg_names) or 'None'}")
            logger.debug(f"  Known tainted variables: {list(self.tainted.keys())}")
            if hasattr(self, "file_handles") and self.file_handles:
                logger.debug(f"  Known file handles: {list(self.file_handles.keys())}")

    def visit_With(self, node: ast.With) -> None:
        """
        Visit a with statement to track file handles for taint tracking.

        Args:
            node: AST node representing a with statement
        """
        for item in node.items:
            if isinstance(item.context_expr, ast.Call):
                func_name, full_name = self._get_func_name_with_module(
                    item.context_expr.func
                )

                if func_name == "open" and len(item.context_expr.args) >= 1:
                    path_arg = item.context_expr.args[0]
                    if (
                        isinstance(item.optional_vars, ast.Name)
                        and isinstance(path_arg, ast.Name)
                        and path_arg.id in self.tainted
                    ):
                        file_handle_name = item.optional_vars.id

                        if not hasattr(self, "file_handles"):
                            self.file_handles = {}

                        self.file_handles[file_handle_name] = {
                            "source_var": path_arg.id,
                            "source_info": self.tainted[path_arg.id],
                        }

                        if self.debug:
                            logger.debug(
                                f"Tracking file handle '{file_handle_name}' from tainted path '{path_arg.id}' in with statement"
                            )

        self.generic_visit(node)

    def _get_sink_vulnerability_type(self, sink_type: str) -> str:
        """
        Get the vulnerability type corresponding to the sink type.

        Args:
            sink_type: The type name of the sink

        Returns:
            The vulnerability type name
        """
        vulnerability_map = {
            "SQLQuery": "SQL Injection",
            "CommandExecution": "Command Injection",
            "FileOperation": "Path Traversal",
            "ResponseData": "Cross-Site Scripting",
            "TemplateOperation": "Template Injection",
            "Deserialization": "Deserialization Attack",
            "XMLOperation": "XXE Injection",
        }

        if sink_type in vulnerability_map:
            return vulnerability_map[sink_type]

        for sink in self.sinks:
            if sink.get("name") == sink_type and "vulnerability_type" in sink:
                return sink["vulnerability_type"]

        return f"{sink_type} Vulnerability"
