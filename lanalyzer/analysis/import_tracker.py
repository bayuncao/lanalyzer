"""import_tracker.py
专门负责解析并记录 Python 源文件中的 import 语句，提取别名映射等信息。

该模块原本嵌入在 `ast_parser.TaintVisitor` 内部，现单独拆分以便复用与测试。
增强版本支持详细的导入信息收集，包括标准库和第三方库的识别。
"""
from __future__ import annotations

import ast
import sys
import importlib.util
from typing import Dict, Set, Optional, List, Any

from lanalyzer.logger import get_logger

logger = get_logger("lanalyzer.analysis.import_tracker")


class ImportTracker(ast.NodeVisitor):
    """AST 访问器，用于追踪 import/from import 的别名与模块映射。

    增强版本支持详细的导入信息收集，包括：
    - 标准库识别
    - 第三方库识别
    - 导入的具体方法和类
    - 导入位置信息
    """

    def __init__(self, debug_mode: bool = False) -> None:
        self.debug = debug_mode

        # 原有的别名映射（保持向后兼容）
        self.import_aliases: Dict[str, str] = {}
        self.from_imports: Dict[str, str] = {}
        self.direct_imports: Set[str] = set()

        # 新增的详细导入信息
        self.detailed_imports: List[Dict[str, Any]] = []
        self.imported_modules: Set[str] = set()
        self.imported_functions: Set[str] = set()
        self.imported_classes: Set[str] = set()
        self.standard_library_imports: Set[str] = set()
        self.third_party_imports: Set[str] = set()

        # 预定义的标准库模块（Python 3.x常见标准库）
        self.stdlib_modules = {
            'os', 'sys', 'json', 'pickle', 'subprocess', 'socket', 'urllib', 'http',
            'ast', 're', 'collections', 'itertools', 'functools', 'operator',
            'datetime', 'time', 'random', 'math', 'statistics', 'decimal',
            'pathlib', 'glob', 'shutil', 'tempfile', 'zipfile', 'tarfile',
            'csv', 'xml', 'html', 'email', 'base64', 'hashlib', 'hmac',
            'sqlite3', 'logging', 'argparse', 'configparser', 'unittest',
            'threading', 'multiprocessing', 'asyncio', 'concurrent',
            'io', 'struct', 'array', 'weakref', 'copy', 'pprint',
            'warnings', 'contextlib', 'abc', 'typing', 'dataclasses',
            'enum', 'inspect', 'importlib', 'pkgutil', 'modulefinder',
            'platform', 'ctypes', 'mmap', 'select', 'signal', 'errno',
        }

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

            # 原有逻辑（保持向后兼容）
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

            # 新增的详细信息收集
            self._record_detailed_import(
                import_type="import",
                module_name=name.name,
                imported_name=None,
                alias=name.asname,
                line_number=getattr(node, 'lineno', 0),
                col_offset=getattr(node, 'col_offset', 0)
            )

        # 继续遍历子节点（import 语句一般无子节点，但保持一致）
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        """记录 `from module import ...` 形式。"""
        if node.module:
            for name in node.names:
                imported_name = name.name
                full_name = f"{node.module}.{imported_name}"

                # 原有逻辑（保持向后兼容）
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

                # 新增的详细信息收集
                self._record_detailed_import(
                    import_type="from_import",
                    module_name=node.module,
                    imported_name=imported_name,
                    alias=name.asname,
                    line_number=getattr(node, 'lineno', 0),
                    col_offset=getattr(node, 'col_offset', 0)
                )
        else:
            # 处理相对导入 (from . import xxx)
            for name in node.names:
                self._record_detailed_import(
                    import_type="relative_import",
                    module_name=".",
                    imported_name=name.name,
                    alias=name.asname,
                    line_number=getattr(node, 'lineno', 0),
                    col_offset=getattr(node, 'col_offset', 0)
                )

        self.generic_visit(node)

    # -----------------------------------------------------------------------------

    # Utility helpers -------------------------------------------------------------

    def resolve_name(self, alias: str) -> Optional[str]:
        """尝试解析别名对应的完整模块名。"""
        return self.import_aliases.get(alias) or self.from_imports.get(alias)

    def _record_detailed_import(self, import_type: str, module_name: str,
                               imported_name: Optional[str] = None,
                               alias: Optional[str] = None,
                               line_number: int = 0, col_offset: int = 0) -> None:
        """记录详细的导入信息。"""
        # 确定根模块名（用于标准库/第三方库判断）
        root_module = module_name.split('.')[0] if module_name else ""

        # 判断是否为标准库
        is_stdlib = self._is_standard_library(root_module)

        # 创建详细导入记录
        import_record = {
            "type": import_type,
            "module": module_name,
            "imported_name": imported_name,
            "alias": alias,
            "line": line_number,
            "col": col_offset,
            "is_stdlib": is_stdlib,
            "root_module": root_module,
        }

        self.detailed_imports.append(import_record)

        # 更新各种集合
        if module_name:
            self.imported_modules.add(module_name)
            if is_stdlib:
                self.standard_library_imports.add(root_module)
            else:
                self.third_party_imports.add(root_module)

        if imported_name:
            # 尝试判断是函数还是类（基于命名约定）
            if imported_name[0].isupper():
                self.imported_classes.add(imported_name)
            else:
                self.imported_functions.add(imported_name)

        if self.debug:
            logger.debug(f"  Detailed import recorded: {import_record}")

    def _is_standard_library(self, module_name: str) -> bool:
        """判断模块是否为Python标准库。"""
        if not module_name:
            return False

        # 检查预定义的标准库列表
        if module_name in self.stdlib_modules:
            return True

        # 检查一些常见的标准库前缀
        stdlib_prefixes = ['urllib', 'xml', 'html', 'email', 'http', 'concurrent']
        for prefix in stdlib_prefixes:
            if module_name.startswith(prefix):
                return True

        # 尝试通过importlib检查（可能会有性能影响，但更准确）
        try:
            import importlib.util
            spec = importlib.util.find_spec(module_name)
            if spec and spec.origin:
                # 标准库通常在Python安装目录下
                import sys
                python_path = sys.executable
                stdlib_path = python_path.replace('python', '').replace('Python', '')
                return stdlib_path in spec.origin
        except (ImportError, AttributeError, ValueError):
            pass

        return False

    def get_import_summary(self) -> Dict[str, Any]:
        """获取导入信息的摘要。"""
        return {
            "total_imports": len(self.detailed_imports),
            "unique_modules": len(self.imported_modules),
            "standard_library_modules": sorted(list(self.standard_library_imports)),
            "third_party_modules": sorted(list(self.third_party_imports)),
            "imported_functions": sorted(list(self.imported_functions)),
            "imported_classes": sorted(list(self.imported_classes)),
            "detailed_imports": self.detailed_imports,
        }