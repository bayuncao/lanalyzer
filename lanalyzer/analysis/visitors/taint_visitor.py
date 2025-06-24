"""visitors/taint_visitor.py
临时包装旧的 TaintVisitor，后续将迁移代码并从 ast_parser 精简。
"""
from __future__ import annotations

# 为兼容旧实现，尝试从 ast_parser 引入剩余方法；若因循环依赖失败，则退化为 object。
try:
    from lanalyzer.analysis.ast_parser import TaintVisitor as _LegacyTaintVisitor  # type: ignore
except ImportError:  # pragma: no cover
    _LegacyTaintVisitor = object  # type: ignore


class TaintVisitor(_LegacyTaintVisitor):
    """包装类，直接继承旧实现。

    后续步骤：
    1. 将 `_LegacyTaintVisitor` 代码迁移到此文件。
    2. 从 `ast_parser.py` 中删除原实现，仅保留装配逻辑。
    """

    def _print_function_args(self, node):  # type: ignore
        """从旧实现迁移：打印函数调用参数，供调试使用。"""
        import ast as _ast

        args = []
        for arg in node.args:  # type: ignore
            if isinstance(arg, _ast.Name):
                args.append(f"Name({arg.id})")
            elif isinstance(arg, _ast.Constant):
                args.append(f"Constant({repr(arg.value)})")
            elif isinstance(arg, _ast.Call):
                func_name, _ = self._get_func_name_with_module(arg.func)
                args.append(f"Call({func_name})")
            else:
                args.append(type(arg).__name__)

        kws = []
        for kw in node.keywords:  # type: ignore
            if isinstance(kw.value, _ast.Name):
                kws.append(f"{kw.arg}=Name({kw.value.id})")
            elif isinstance(kw.value, _ast.Constant):
                kws.append(f"{kw.arg}=Constant({repr(kw.value.value)})")
            else:
                kws.append(f"{kw.arg}={type(kw.value).__name__}")

        from lanalyzer.logger import get_logger

        logger = get_logger("lanalyzer.analysis.visitors.taint_visitor")
        logger.debug(f"  Args: {', '.join(args)}")
        if kws:
            logger.debug(f"  Keywords: {', '.join(kws)}")

    def _get_func_name_with_module(self, func):  # type: ignore
        """迁移自旧 TaintVisitor：结合导入别名解析函数全名"""
        import ast as _ast
        from typing import Optional, Tuple
        from lanalyzer.logger import get_logger

        logger = get_logger("lanalyzer.analysis.visitors.taint_visitor")

        if self.debug:
            logger.debug(f"\n[Function Name Parsing] Starting parsing: {_ast.dump(func)}")

        if func is None:
            if self.debug:
                logger.debug("  Function node is None")
            return None, None

        if isinstance(func, _ast.Name):
            simple_name = func.id

            if simple_name in self.from_imports:
                full_name = self.from_imports[simple_name]
                return simple_name, full_name

            if simple_name in self.import_aliases:
                module_name = self.import_aliases[simple_name]
                return simple_name, module_name

            if simple_name in self.direct_imports:
                return simple_name, simple_name

            return simple_name, simple_name

        elif isinstance(func, _ast.Attribute):
            if isinstance(func.value, _ast.Name):
                module_name = func.value.id
                attr_name = func.attr

                if module_name in self.import_aliases:
                    real_module = self.import_aliases[module_name]
                    full_name = f"{real_module}.{attr_name}"
                else:
                    full_name = f"{module_name}.{attr_name}"

                return attr_name, full_name

            elif isinstance(func.value, _ast.Attribute):
                _, parent_full = self._get_func_name_with_module(func.value)
                if parent_full:
                    full_name = f"{parent_full}.{func.attr}"
                    return func.attr, full_name

        try:
            expr_str = _ast.unparse(func)
            return expr_str, None
        except (AttributeError, ValueError):
            pass

        return None, None

    def _track_assignment_taint(self, node, source_info):  # type: ignore
        """迁移自旧 TaintVisitor：在赋值语句中传播污点。"""
        import ast as _ast
        from lanalyzer.logger import get_logger

        logger = get_logger("lanalyzer.analysis.visitors.taint_visitor")

        if hasattr(node, "parent"):
            parent = node.parent  # type: ignore

            if isinstance(parent, _ast.Assign):
                for target in parent.targets:
                    if isinstance(target, _ast.Name):
                        self.tainted[target.id] = source_info  # type: ignore[attr-defined]
                        if self.debug:
                            logger.debug(
                                f"Tainted variable '{target.id}' from direct assignment at line {getattr(parent, 'lineno', 0)}"
                            )

            elif isinstance(parent, _ast.AugAssign) and isinstance(parent.target, _ast.Name):
                self.tainted[parent.target.id] = source_info  # type: ignore[attr-defined]
                if self.debug:
                    logger.debug(
                        f"Tainted variable '{parent.target.id}' from augmented assignment at line {getattr(parent, 'lineno', 0)}"
                    )

            elif isinstance(parent, _ast.For) and node == parent.iter:
                if isinstance(parent.target, _ast.Name):
                    self.tainted[parent.target.id] = source_info  # type: ignore[attr-defined]
                    if self.debug:
                        logger.debug(
                            f"Tainted variable '{parent.target.id}' from for loop at line {getattr(parent, 'lineno', 0)}"
                        )
                elif isinstance(parent.target, _ast.Tuple):
                    for elt in parent.target.elts:
                        if isinstance(elt, _ast.Name):
                            self.tainted[elt.id] = source_info  # type: ignore[attr-defined]
                            if self.debug:
                                logger.debug(
                                    f"Tainted variable '{elt.id}' from for loop tuple unpacking at line {getattr(parent, 'lineno', 0)}"
                                )

    def visit_Assign(self, node):  # type: ignore
        """迁移自旧 TaintVisitor: 处理赋值并传播污点。"""
        import ast as _ast
        from lanalyzer.logger import get_logger

        logger = get_logger("lanalyzer.analysis.visitors.taint_visitor")

        if isinstance(node.value, _ast.Call):
            func_name, full_name = self._get_func_name_with_module(node.value.func)

            if self.debug:
                logger.debug(
                    f"Checking assignment with function call: {func_name} (full: {full_name}) at line {getattr(node, 'lineno', 0)}"
                )

            if func_name and self._is_source(func_name, full_name):  # type: ignore[attr-defined]
                source_type = self._get_source_type(func_name, full_name)  # type: ignore[attr-defined]
                line_no = getattr(node.value, "lineno", 0)
                col_offset = getattr(node.value, "col_offset", 0)

                source_info = {
                    "name": source_type,
                    "line": line_no,
                    "col": col_offset,
                    "node": node.value,
                }

                self.found_sources.append(source_info)  # type: ignore[attr-defined]

                if self.debug:
                    logger.debug(
                        f"Found source in assignment: {source_type} at line {line_no}"
                    )

                for target in node.targets:
                    if isinstance(target, _ast.Name):
                        self.tainted[target.id] = source_info  # type: ignore[attr-defined]
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

                self.found_sources.append(source_info)  # type: ignore[attr-defined]

                for target in node.targets:
                    if isinstance(target, _ast.Name):
                        self.tainted[target.id] = source_info  # type: ignore[attr-defined]
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

                self.found_sources.append(source_info)  # type: ignore[attr-defined]

                for target in node.targets:
                    if isinstance(target, _ast.Name):
                        self.tainted[target.id] = source_info  # type: ignore[attr-defined]
                        if self.debug:
                            logger.debug(
                                f"Tainted variable '{target.id}' from EnvironmentVariables at line {line_no}"
                            )

            elif func_name == "read" and isinstance(node.value.func, _ast.Attribute):
                line_no = getattr(node.value, "lineno", 0)
                col_offset = getattr(node.value, "col_offset", 0)

                source_info = {
                    "name": "FileRead",
                    "line": line_no,
                    "col": col_offset,
                    "node": node.value,
                }

                self.found_sources.append(source_info)  # type: ignore[attr-defined]

                for target in node.targets:
                    if isinstance(target, _ast.Name):
                        self.tainted[target.id] = source_info  # type: ignore[attr-defined]
                        if self.debug:
                            logger.debug(
                                f"Tainted variable '{target.id}' from FileRead at line {line_no}"
                            )

        elif isinstance(node.value, _ast.Name) and node.value.id in self.tainted:  # type: ignore[attr-defined]
            for target in node.targets:
                if isinstance(target, _ast.Name):
                    self.tainted[target.id] = self.tainted[node.value.id]  # type: ignore[attr-defined]
                    if self.debug:
                        logger.debug(
                            f"Propagated taint from {node.value.id} to {target.id} at line {getattr(node, 'lineno', 0)}"
                        )

        elif isinstance(node.value, _ast.Attribute) and isinstance(node.value.value, _ast.Name):
            if node.value.value.id in self.tainted:  # type: ignore[attr-defined]
                for target in node.targets:
                    if isinstance(target, _ast.Name):
                        self.tainted[target.id] = self.tainted[node.value.value.id]  # type: ignore[attr-defined]
                        if self.debug:
                            logger.debug(
                                f"Propagated taint from {node.value.value.id}.{node.value.attr} to {target.id} at line {getattr(node, 'lineno', 0)}"
                            )

        elif isinstance(node.value, _ast.Subscript) and isinstance(node.value.value, _ast.Name):
            if node.value.value.id in self.tainted:  # type: ignore[attr-defined]
                for target in node.targets:
                    if isinstance(target, _ast.Name):
                        self.tainted[target.id] = self.tainted[node.value.value.id]  # type: ignore[attr-defined]
                        if self.debug:
                            logger.debug(
                                f"Propagated taint from {node.value.value.id}[...] to {target.id} at line {getattr(node, 'lineno', 0)}"
                            )

        elif (
            isinstance(node.value, _ast.Subscript)
            and isinstance(node.value.value, _ast.Attribute)
            and node.value.value.attr == "argv"
            and isinstance(node.value.value.value, _ast.Name)
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

            self.found_sources.append(source_info)  # type: ignore[attr-defined]

            for target in node.targets:
                if isinstance(target, _ast.Name):
                    self.tainted[target.id] = source_info  # type: ignore[attr-defined]
                    if self.debug:
                        logger.debug(
                            f"Tainted variable '{target.id}' from CommandLineArgs at line {line_no}"
                        )

        self.generic_visit(node)

    def _check_sink_args(self, node, sink_type, sink_info=None):  # type: ignore
        """迁移自旧 TaintVisitor：检查传入 sink 的参数是否 tainted。
        为简化，此实现直接委托旧实现（若存在）以保持行为；后续可在此文件细化优化。"""
        try:
            from lanalyzer.analysis.ast_parser import TaintVisitor as _Legacy
            return _Legacy._check_sink_args(self, node, sink_type, sink_info)  # type: ignore
        except Exception:  # noqa: BLE001
            # 若旧实现不可用，保持现状不处理
            return