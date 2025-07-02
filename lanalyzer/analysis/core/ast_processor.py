"""
Unified AST processing module.

This module consolidates all AST-related functionality including:
- AST parsing and parent node mapping
- Source line handling and context extraction
- Import tracking and resolution
"""

import ast
from typing import Any, Dict, List, Optional, Tuple

from lanalyzer.logger import debug, get_logger

logger = get_logger("lanalyzer.analysis.core.ast_processor")


class ParentNodeVisitor(ast.NodeVisitor):
    """
    AST visitor that adds parent references to nodes.
    Consolidated from multiple implementations.
    """

    def __init__(self):
        self.parent_map: Dict[ast.AST, ast.AST] = {}

    def visit(self, node: ast.AST) -> None:
        """Visit a node and add parent references to its children."""
        for child in ast.iter_child_nodes(node):
            self.parent_map[child] = node
        super().visit(node)


class ASTProcessor:
    """
    Unified AST processor that handles parsing, parent mapping, and source line management.
    """

    def __init__(self, debug_mode: bool = False):
        self.debug = debug_mode
        self.logger = logger

    def parse_file(
        self, file_path: str
    ) -> Tuple[Optional[ast.AST], Optional[List[str]], Dict[ast.AST, ast.AST]]:
        """
        Parse a Python file and return AST, source lines, and parent map.

        Args:
            file_path: Path to the Python file

        Returns:
            Tuple of (AST tree, source lines, parent map)
        """
        try:
            # Read file only once
            with open(file_path, "r", encoding="utf-8") as f:
                source_lines = f.readlines()
                code = "".join(source_lines)

        except FileNotFoundError as e:
            if self.debug:
                self.logger.error(f"File not found: {file_path}: {e}")
            return None, None, {}
        except PermissionError as e:
            if self.debug:
                self.logger.error(f"Permission denied reading {file_path}: {e}")
            return None, None, {}
        except UnicodeDecodeError as e:
            if self.debug:
                self.logger.error(f"Unicode decode error reading {file_path}: {e}")
            # Try with different encodings
            for encoding in ["latin-1", "cp1252", "iso-8859-1"]:
                try:
                    with open(file_path, "r", encoding=encoding) as f:
                        source_lines = f.readlines()
                        code = "".join(source_lines)
                    if self.debug:
                        self.logger.info(
                            f"Successfully read {file_path} with {encoding} encoding"
                        )
                    break
                except Exception:
                    continue
            else:
                if self.debug:
                    self.logger.error(f"Failed to read {file_path} with any encoding")
                return None, None, {}
        except MemoryError as e:
            if self.debug:
                self.logger.error(f"Memory error reading {file_path}: {e}")
            return None, None, {}
        except Exception as e:
            if self.debug:
                self.logger.error(f"Unexpected error reading {file_path}: {e}")
            return None, None, {}

        try:
            tree = ast.parse(code, filename=file_path)
        except SyntaxError as e:
            if self.debug:
                self.logger.error(
                    f"Syntax error in {file_path} at line {e.lineno}, offset {e.offset}: {e.msg}"
                )
            return None, source_lines, {}
        except UnicodeDecodeError as e:
            if self.debug:
                self.logger.error(f"Unicode decode error in {file_path}: {e}")
            return None, source_lines, {}
        except MemoryError as e:
            if self.debug:
                self.logger.error(f"Memory error parsing {file_path}: {e}")
            return None, source_lines, {}
        except RecursionError as e:
            if self.debug:
                self.logger.error(
                    f"Recursion error parsing {file_path} (file too complex): {e}"
                )
            return None, source_lines, {}
        except Exception as e:
            if self.debug:
                self.logger.error(f"Unexpected error parsing {file_path}: {e}")
            return None, source_lines, {}

        # Add parent references
        parent_visitor = ParentNodeVisitor()
        parent_visitor.visit(tree)

        if self.debug:
            self.logger.debug(
                f"Successfully parsed {file_path} with {len(source_lines)} lines"
            )

        return tree, source_lines, parent_visitor.parent_map

    def get_statement_at_line(
        self, source_lines: List[str], line: int, context_lines: int = 0
    ) -> Dict[str, Any]:
        """
        Extract statement at specified line with optional context.

        Args:
            source_lines: List of source code lines
            line: Target line number (1-based)
            context_lines: Number of context lines to include

        Returns:
            Dictionary containing statement and context information
        """
        if line <= 0 or line > len(source_lines):
            return {"statement": "", "context_start": line, "context_end": line}

        statement = source_lines[line - 1].strip()
        start_line = max(1, line - context_lines)
        end_line = min(len(source_lines), line + context_lines)

        context = None
        if context_lines > 0:
            context = [
                f"{i}: {source_lines[i - 1].rstrip()}"
                for i in range(start_line, end_line + 1)
            ]

        return {
            "statement": statement,
            "context_lines": context,
            "context_start": start_line,
            "context_end": end_line,
        }

    def extract_operation_at_line(
        self,
        source_lines: List[str],
        line: int,
        dangerous_patterns: Optional[Dict[str, List[str]]] = None,
    ) -> Optional[str]:
        """
        Extract operation string at specified line for pattern matching.

        Args:
            source_lines: List of source code lines
            line: Target line number (1-based)
            dangerous_patterns: Dictionary of dangerous patterns to match

        Returns:
            Operation string if found, None otherwise
        """
        if line <= 0 or line > len(source_lines):
            if self.debug:
                debug(f"[ASTProcessor] Line {line} out of range.")
            return None

        line_content = source_lines[line - 1].strip()

        # Extract right-hand side of assignment or full line
        operation = (
            line_content.split("=", 1)[1].strip()
            if "=" in line_content
            else line_content
        )

        # Clean up comments and semicolons
        import re

        operation = re.sub(r"[;].*$", "", operation)
        operation = re.sub(r"#.*$", "", operation).strip()

        if dangerous_patterns:
            for sink_name, patterns in dangerous_patterns.items():
                for pattern in patterns:
                    if pattern in operation:
                        return operation

        return operation or None

    def get_func_name_with_module(
        self, func_node: ast.expr
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract function name and full module path from function call node.

        Args:
            func_node: AST node representing function call

        Returns:
            Tuple of (function name, full module path)
        """
        if isinstance(func_node, ast.Name):
            return func_node.id, func_node.id
        elif isinstance(func_node, ast.Attribute):
            if isinstance(func_node.value, ast.Name):
                return func_node.attr, f"{func_node.value.id}.{func_node.attr}"
            elif isinstance(func_node.value, ast.Attribute):
                # Handle nested attributes like os.path.join
                parts = []
                current = func_node
                while isinstance(current, ast.Attribute):
                    parts.append(current.attr)
                    current = current.value
                if isinstance(current, ast.Name):
                    parts.append(current.id)
                    full_name = ".".join(reversed(parts))
                    return func_node.attr, full_name

        return None, None
