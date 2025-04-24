"""
Definition-use chain analysis for enhanced taint tracking.
"""

import ast
from typing import Any, List, Tuple


class DefUseChain:
    """
    Represents a definition-use chain for a variable.
    """

    def __init__(self, name: str):
        self.name = name
        self.definitions = []  # (ast_node, line_no) pairs
        self.uses = []  # (ast_node, line_no) pairs
        self.tainted = False
        self.taint_sources = []

    def add_definition(self, node: ast.AST, line_no: int) -> None:
        """Add a definition site for this variable."""
        self.definitions.append((node, line_no))

    def add_use(self, node: ast.AST, line_no: int) -> None:
        """Add a use site for this variable."""
        self.uses.append((node, line_no))

    def mark_tainted(self, source_info: Any) -> None:
        """Mark variable as tainted with the given source info."""
        self.tainted = True
        if source_info not in self.taint_sources:
            self.taint_sources.append(source_info)

    def get_propagation_path(self) -> List[Tuple[str, int]]:
        """Get the propagation path for this variable."""
        path = []

        # Add definitions in order
        for node, line in sorted(self.definitions, key=lambda x: x[1]):
            path.append(("definition", line))

        # Add uses in order
        for node, line in sorted(self.uses, key=lambda x: x[1]):
            path.append(("use", line))

        return path

    def __repr__(self) -> str:
        return f"DefUseChain(name='{self.name}', tainted={self.tainted}, defs={len(self.definitions)}, uses={len(self.uses)})"
