"""
Call graph implementation for enhanced taint analysis.
"""

import ast
from typing import Optional, List, Dict, Any  # Added List, Dict, Any for type hints


class CallGraphNode:
    """
    Represents a node in the call graph, corresponding to a function or method.
    """

    def __init__(
        self,
        name: str,
        ast_node: Optional[ast.FunctionDef] = None,
        file_path: Optional[str] = None,
        line_no: int = 0,
        end_line_no: int = 0,
    ):
        self.name: str = name
        self.ast_node: Optional[ast.FunctionDef] = ast_node
        self.file_path: Optional[str] = file_path
        self.line_no: int = line_no
        self.end_line_no: int = end_line_no if end_line_no > 0 else line_no
        self.callers: List[
            "CallGraphNode"
        ] = []  # List of nodes that call this function
        self.callees: List[
            "CallGraphNode"
        ] = []  # List of nodes that this function calls
        self.parameters: List[str] = []  # List of parameter names
        self.tainted_parameters: set[
            int
        ] = set()  # Set of parameter indices that are tainted
        self.return_tainted: bool = False  # Whether this function returns tainted data
        self.return_taint_sources: List[Any] = []  # Sources of taint for return values

        # Add call point information
        self.call_line: int = (
            0  # Line number where this function is called (often the latest one added)
        )
        self.call_points: List[
            Dict[str, Any]
        ] = []  # Detailed information for all call points
        self.is_self_method_call: bool = False  # Whether it is a self.method() call
        self.self_method_name: Optional[
            str
        ] = None  # If it is a self method call, record the method name

    def add_caller(self, caller: "CallGraphNode") -> None:
        """Adds a caller to this node if not already present."""
        if caller not in self.callers:
            self.callers.append(caller)

    def add_callee(self, callee: "CallGraphNode") -> None:
        """Adds a callee to this node if not already present."""
        if callee not in self.callees:
            self.callees.append(callee)

    def add_call_point(self, line_no: int, statement: str, caller_name: str) -> None:
        """Add detailed call point information."""
        call_point = {"line": line_no, "statement": statement, "caller": caller_name}
        self.call_points.append(call_point)
        self.call_line = (
            line_no  # Update the most recent call line number (can be one of many)
        )

    def __repr__(self) -> str:
        return f"CallGraphNode(name='{self.name}', file='{self.file_path}', line={self.line_no}, end_line={self.end_line_no})"
