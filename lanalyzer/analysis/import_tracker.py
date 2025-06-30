"""import_tracker.py
Specialized import parsing and recording in Python source files, extracting alias mappings, etc.

This module was originally embedded in `ast_parser.TaintVisitor`, now split to be reused and tested.
Enhanced version supports detailed import information collection, including recognition of standard and third-party libraries.

This module is responsible for parsing and recording import statements in Python source files,
extracting alias mappings, etc.
"""
from __future__ import annotations

import ast
from typing import Any, Dict, List, Optional, Set

from lanalyzer.logger import get_logger
from lanalyzer.utils.stdlib_detector import get_stdlib_detector

logger = get_logger("lanalyzer.analysis.import_tracker")


class ImportTracker(ast.NodeVisitor):
    """AST visitor for tracking import and from-import aliases and module mappings.

    Enhanced version supports detailed import information collection, including:
    - Standard library recognition
    - Third-party library recognition
    - Imported specific methods and classes
    - Import location information

    """

    def __init__(self, debug_mode: bool = False) -> None:
        self.debug = debug_mode

        # Original alias mapping (for backward compatibility)
        self.import_aliases: Dict[str, str] = {}
        self.from_imports: Dict[str, str] = {}
        self.direct_imports: Set[str] = set()

        # New detailed import information
        self.detailed_imports: List[Dict[str, Any]] = []
        self.imported_modules: Set[str] = set()
        self.imported_functions: Set[str] = set()
        self.imported_classes: Set[str] = set()
        self.standard_library_imports: Set[str] = set()
        self.third_party_imports: Set[str] = set()

        # Initialize standard library detector
        self.stdlib_detector = get_stdlib_detector(debug=self.debug)

    # --- ast.NodeVisitor overrides -------------------------------------------------

    def visit_Import(
        self, node: ast.Import
    ) -> None:  # noqa: N802 (consistent with ast API)
        """Record `import xxx as yyy` and direct import situations."""
        for name in node.names:
            if self.debug:
                logger.debug(
                    f"[ImportTracker] Processing import: {name.name}"
                    + (f" as {name.asname}" if name.asname else "")
                )

            # Record import information
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

            # Record detailed information
            self._record_detailed_import(
                import_type="import",
                module_name=name.name,
                imported_name=None,
                alias=name.asname,
                line_number=getattr(node, "lineno", 0),
                col_offset=getattr(node, "col_offset", 0),
            )

        # Continue to traverse child nodes (import statements usually have no children, but consistent)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        """Record `from module import ...` form."""
        if node.module:
            for name in node.names:
                imported_name = name.name
                full_name = f"{node.module}.{imported_name}"

                # Original logic (for backward compatibility)
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

                # New detailed information collection
                self._record_detailed_import(
                    import_type="from_import",
                    module_name=node.module,
                    imported_name=imported_name,
                    alias=name.asname,
                    line_number=getattr(node, "lineno", 0),
                    col_offset=getattr(node, "col_offset", 0),
                )
        else:
            # Handle relative imports (from . import xxx)
            for name in node.names:
                self._record_detailed_import(
                    import_type="relative_import",
                    module_name=".",
                    imported_name=name.name,
                    alias=name.asname,
                    line_number=getattr(node, "lineno", 0),
                    col_offset=getattr(node, "col_offset", 0),
                )

        self.generic_visit(node)

    # -----------------------------------------------------------------------------

    # Utility helpers -------------------------------------------------------------

    def resolve_name(self, alias: str) -> Optional[str]:
        """Try to resolve the full module name corresponding to an alias."""
        return self.import_aliases.get(alias) or self.from_imports.get(alias)

    def _record_detailed_import(
        self,
        import_type: str,
        module_name: str,
        imported_name: Optional[str] = None,
        alias: Optional[str] = None,
        line_number: int = 0,
        col_offset: int = 0,
    ) -> None:
        """Record detailed import information."""
        # Determine the root module name (for standard library/third-party library judgment)
        root_module = module_name.split(".")[0] if module_name else ""

        # Judge whether it is a standard library
        is_stdlib = self._is_standard_library(root_module)

        # Create detailed import record
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

        # Update various collections
        if module_name:
            self.imported_modules.add(module_name)
            if is_stdlib:
                self.standard_library_imports.add(root_module)
            else:
                self.third_party_imports.add(root_module)

        if imported_name:
            # Try to judge whether it is a function or class (based on naming convention)
            if imported_name[0].isupper():
                self.imported_classes.add(imported_name)
            else:
                self.imported_functions.add(imported_name)

        if self.debug:
            logger.debug(f"  Detailed import recorded: {import_record}")

    def _is_standard_library(self, module_name: str) -> bool:
        """Judge whether a module is a Python standard library."""
        return self.stdlib_detector.is_standard_library(module_name)

    def get_import_summary(self) -> Dict[str, Any]:
        """Get summary of import information."""
        return {
            "total_imports": len(self.detailed_imports),
            "unique_modules": len(self.imported_modules),
            "standard_library_modules": sorted(list(self.standard_library_imports)),
            "third_party_modules": sorted(list(self.third_party_imports)),
            "imported_functions": sorted(list(self.imported_functions)),
            "imported_classes": sorted(list(self.imported_classes)),
            "detailed_imports": self.detailed_imports,
        }
