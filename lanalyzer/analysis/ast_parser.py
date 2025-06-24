import ast
import re
import os
from typing import Any, Dict, Optional, Tuple
from lanalyzer.logger import get_logger
from lanalyzer.analysis.import_tracker import ImportTracker
from lanalyzer.analysis.source_sink_classifier import SourceSinkClassifier

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
        """TaintVisitor 构造函数，现委托 ImportTracker 处理 import 解析。"""

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

        # Import tracking delegated to ImportTracker
        self.import_tracker = ImportTracker(debug_mode=self.debug)
        self.import_aliases = self.import_tracker.import_aliases
        self.from_imports = self.import_tracker.from_imports
        self.direct_imports = self.import_tracker.direct_imports

        # Source/Sink 分类器
        self.classifier = SourceSinkClassifier(self)

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        self.import_tracker.visit_Import(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        self.import_tracker.visit_ImportFrom(node)

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

    def visit_Assign(self, node):  # type: ignore
        from lanalyzer.analysis.visitors import taint_visitor as _tv
        return _tv.TaintVisitor.visit_Assign(self, node)

    def _get_func_name_with_module(self, func: ast.expr):  # type: ignore
        from lanalyzer.analysis.visitors import taint_visitor as _tv  # local import to avoid circularity
        return _tv.TaintVisitor._get_func_name_with_module(self, func)  # type: ignore

    def _is_source(self, func_name: str, full_name: Optional[str] = None) -> bool:
        """委托 SourceSinkClassifier 判断是否为 taint 源。"""
        return self.classifier.is_source(func_name, full_name)

    def _get_source_type(self, func_name: str, full_name: Optional[str] = None) -> str:
        return self.classifier.source_type(func_name, full_name)

    def _is_sink(self, func_name: str, full_name: Optional[str] = None) -> bool:
        return self.classifier.is_sink(func_name, full_name)

    def _get_sink_type(self, func_name: str, full_name: Optional[str] = None) -> str:
        return self.classifier.sink_type(func_name, full_name)

    def _get_sink_vulnerability_type(self, sink_type: str) -> str:
        return self.classifier.sink_vulnerability_type(sink_type)

    def _track_assignment_taint(self, node: ast.Call, source_info: Dict[str, Any]):  # type: ignore
        from lanalyzer.analysis.visitors import taint_visitor as _tv
        return _tv.TaintVisitor._track_assignment_taint(self, node, source_info)

    def _check_sink_args(self, node: ast.Call, sink_type: str, sink_info: Optional[Dict[str, Any]] = None):  # type: ignore
        from lanalyzer.analysis.visitors import taint_visitor as _tv
        return _tv.TaintVisitor._check_sink_args(self, node, sink_type, sink_info)

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
