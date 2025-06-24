"""import_tracker.py
专门负责解析并记录 Python 源文件中的 import 语句，提取别名映射等信息。

该模块原本嵌入在 `ast_parser.TaintVisitor` 内部，现单独拆分以便复用与测试。
"""
from __future__ import annotations

import ast
from typing import Dict, Set, Optional

from lanalyzer.logger import get_logger

logger = get_logger("lanalyzer.analysis.import_tracker")


class ImportTracker(ast.NodeVisitor):
    """AST 访问器，用于追踪 import/from import 的别名与模块映射。"""

    def __init__(self, debug_mode: bool = False) -> None:
        self.debug = debug_mode
        self.import_aliases: Dict[str, str] = {}
        self.from_imports: Dict[str, str] = {}
        self.direct_imports: Set[str] = set()

    # --- ast.NodeVisitor overrides -------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802 (保持与 ast API 一致)
        """记录 `import xxx as yyy` 及直接 import 情况。"""
        for name in node.names:
            if self.debug:
                logger.debug(
                    f"[ImportTracker] Processing import: {name.name}" + (
                        f" as {name.asname}" if name.asname else ""
                    )
                )

            if name.asname:
                # import xxx as alias
                self.import_aliases[name.asname] = name.name
                if self.debug:
                    logger.debug(f"  Alias recorded: {name.asname} -> {name.name}")
            else:
                # import module (no alias)
                self.direct_imports.add(name.name)
                self.from_imports[name.name] = name.name
                if self.debug:
                    logger.debug(f"  Direct import recorded: {name.name}")
        # 继续遍历子节点（import 语句一般无子节点，但保持一致）
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        """记录 `from module import ...` 形式。"""
        if node.module:
            for name in node.names:
                imported_name = name.name
                full_name = f"{node.module}.{imported_name}"
                if name.asname:
                    self.from_imports[name.asname] = full_name
                    if self.debug:
                        logger.debug(
                            f"  From-import alias: {name.asname} -> {full_name}"
                        )
                else:
                    self.from_imports[imported_name] = full_name
                    if self.debug:
                        logger.debug(f"  From-import: {imported_name} -> {full_name}")
        self.generic_visit(node)

    # -----------------------------------------------------------------------------

    # Utility helpers -------------------------------------------------------------

    def resolve_name(self, alias: str) -> Optional[str]:
        """尝试解析别名对应的完整模块名。"""
        return self.import_aliases.get(alias) or self.from_imports.get(alias) 