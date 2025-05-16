"""
Call graph implementation for enhanced taint analysis.
"""

import ast
from typing import Optional


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
        self.name = name
        self.ast_node = ast_node
        self.file_path = file_path
        self.line_no = line_no
        self.end_line_no = end_line_no if end_line_no > 0 else line_no
        self.callers = []  # List of nodes that call this function
        self.callees = []  # List of nodes that this function calls
        self.parameters = []  # List of parameter names
        self.tainted_parameters = set()  # Set of parameter indices that are tainted
        self.return_tainted = False  # Whether this function returns tainted data
        self.return_taint_sources = []  # Sources of taint for return values

        # 增加调用点信息
        self.call_line = 0  # 被调用的行号
        self.call_points = []  # 所有调用点的详细信息
        self.is_self_method_call = False  # 是否是self.method()调用
        self.self_method_name = None  # 如果是self方法调用，记录方法名

    def add_caller(self, caller: "CallGraphNode") -> None:
        if caller not in self.callers:
            self.callers.append(caller)

    def add_callee(self, callee: "CallGraphNode") -> None:
        if callee not in self.callees:
            self.callees.append(callee)

    def add_call_point(self, line_no: int, statement: str, caller_name: str) -> None:
        """添加详细的调用点信息"""
        call_point = {"line": line_no, "statement": statement, "caller": caller_name}
        self.call_points.append(call_point)
        self.call_line = line_no  # 更新最近的调用行号

    def __repr__(self) -> str:
        return f"CallGraphNode(name='{self.name}', file='{self.file_path}', line={self.line_no}, end_line={self.end_line_no})"
