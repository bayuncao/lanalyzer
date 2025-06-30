"""
Call Chain Tracker for enhanced taint analysis.

This module provides detailed tracking of function call chains and data flow paths
from sources to sinks, enabling more comprehensive vulnerability analysis.
"""

import ast
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from lanalyzer.logger import get_logger

logger = get_logger("lanalyzer.analysis.flow.call_chain_tracker")


@dataclass
class CallChainNode:
    """Represents a node in the call chain."""

    function_name: str
    line_number: int
    column: int
    file_path: str
    node_type: str  # 'source', 'sink', 'intermediate', 'assignment'
    variable_name: Optional[str] = None
    taint_info: Optional[Dict[str, Any]] = None
    arguments: List[str] = field(default_factory=list)
    return_value: Optional[str] = None


@dataclass
class TaintPath:
    """Represents a complete taint propagation path."""

    source_node: CallChainNode
    sink_node: CallChainNode
    intermediate_nodes: List[CallChainNode] = field(default_factory=list)
    tainted_variables: List[str] = field(default_factory=list)
    confidence: float = 1.0
    path_length: int = 0

    def __post_init__(self):
        self.path_length = (
            len(self.intermediate_nodes) + 2
        )  # source + sink + intermediates


class CallChainTracker:
    """Enhanced call chain tracker for detailed taint analysis."""

    def __init__(self, file_path: str, debug: bool = False):
        self.file_path = file_path
        self.debug = debug

        # Call chain tracking
        self.call_chains: List[List[CallChainNode]] = []
        self.current_chain: List[CallChainNode] = []
        self.function_stack: List[str] = []

        # Taint propagation tracking
        self.taint_paths: List[TaintPath] = []
        self.variable_assignments: Dict[str, List[CallChainNode]] = {}
        self.function_calls: Dict[str, List[CallChainNode]] = {}

        # Cross-function tracking
        self.function_parameters: Dict[str, List[str]] = {}
        self.function_returns: Dict[str, List[CallChainNode]] = {}

        # Data flow graph
        self.data_flow_edges: List[Tuple[CallChainNode, CallChainNode]] = []

    def enter_function(
        self, func_name: str, line: int, col: int, parameters: List[str] = None
    ):
        """Track entering a function."""
        self.function_stack.append(func_name)
        self.function_parameters[func_name] = parameters or []

        if self.debug:
            logger.debug(f"[CallChain] Entering function: {func_name} at line {line}")

    def exit_function(
        self, func_name: str, return_node: Optional[CallChainNode] = None
    ):
        """Track exiting a function."""
        if self.function_stack and self.function_stack[-1] == func_name:
            self.function_stack.pop()

        if return_node:
            if func_name not in self.function_returns:
                self.function_returns[func_name] = []
            self.function_returns[func_name].append(return_node)

        if self.debug:
            logger.debug(f"[CallChain] Exiting function: {func_name}")

    def track_source(
        self, node: ast.Call, source_info: Dict[str, Any]
    ) -> CallChainNode:
        """Track a taint source."""
        source_node = CallChainNode(
            function_name=source_info.get("name", "unknown"),
            line_number=source_info.get("line", 0),
            column=source_info.get("col", 0),
            file_path=self.file_path,
            node_type="source",
            taint_info=source_info,
            arguments=self._extract_arguments(node),
        )

        self.current_chain = [source_node]

        if self.debug:
            logger.debug(
                f"[CallChain] Tracked source: {source_node.function_name} at line {source_node.line_number}"
            )

        return source_node

    def track_sink(self, node: ast.Call, sink_info: Dict[str, Any]) -> CallChainNode:
        """Track a taint sink."""
        sink_node = CallChainNode(
            function_name=sink_info.get("name", "unknown"),
            line_number=sink_info.get("line", 0),
            column=sink_info.get("col", 0),
            file_path=self.file_path,
            node_type="sink",
            taint_info=sink_info,
            arguments=self._extract_arguments(node),
        )

        if self.debug:
            logger.debug(
                f"[CallChain] Tracked sink: {sink_node.function_name} at line {sink_node.line_number}"
            )

        return sink_node

    def create_source_node_from_taint(
        self, taint_info: Dict[str, Any]
    ) -> CallChainNode:
        """Create a source node from taint information."""
        source_node = CallChainNode(
            function_name=taint_info.get("name", "unknown"),
            line_number=taint_info.get("line", 0),
            column=taint_info.get("col", 0),
            file_path=self.file_path,
            node_type="source",
            taint_info=taint_info,
            arguments=[],
        )

        if self.debug:
            logger.debug(
                f"[CallChain] Created source node from taint: {source_node.function_name} at line {source_node.line_number}"
            )

        return source_node

    def track_assignment(
        self,
        var_name: str,
        line: int,
        col: int,
        source_node: Optional[CallChainNode] = None,
    ) -> CallChainNode:
        """Track variable assignment."""
        assignment_node = CallChainNode(
            function_name=f"assign_{var_name}",
            line_number=line,
            column=col,
            file_path=self.file_path,
            node_type="assignment",
            variable_name=var_name,
            taint_info=source_node.taint_info if source_node else None,
        )

        # Track variable assignment history
        if var_name not in self.variable_assignments:
            self.variable_assignments[var_name] = []
        self.variable_assignments[var_name].append(assignment_node)

        # Add to current chain
        if self.current_chain:
            self.current_chain.append(assignment_node)

        # Create data flow edge if there's a source
        if source_node:
            self.data_flow_edges.append((source_node, assignment_node))

        if self.debug:
            logger.debug(f"[CallChain] Tracked assignment: {var_name} at line {line}")

        return assignment_node

    def track_function_call(
        self, func_name: str, line: int, col: int, arguments: List[str] = None
    ) -> CallChainNode:
        """Track intermediate function call."""
        call_node = CallChainNode(
            function_name=func_name,
            line_number=line,
            column=col,
            file_path=self.file_path,
            node_type="intermediate",
            arguments=arguments or [],
        )

        # Track function calls
        if func_name not in self.function_calls:
            self.function_calls[func_name] = []
        self.function_calls[func_name].append(call_node)

        # Add to current chain
        if self.current_chain:
            self.current_chain.append(call_node)

        if self.debug:
            logger.debug(
                f"[CallChain] Tracked function call: {func_name} at line {line}"
            )

        return call_node

    def create_taint_path(
        self, source_node: CallChainNode, sink_node: CallChainNode, tainted_var: str
    ) -> TaintPath:
        """Create a complete taint path from source to sink."""
        # Find intermediate nodes
        intermediate_nodes = []

        # Look for variable assignments that connect source to sink
        if tainted_var in self.variable_assignments:
            for assignment in self.variable_assignments[tainted_var]:
                if (
                    source_node.line_number
                    < assignment.line_number
                    < sink_node.line_number
                ):
                    intermediate_nodes.append(assignment)

        # Sort intermediate nodes by line number
        intermediate_nodes.sort(key=lambda x: x.line_number)

        # Calculate confidence based on path complexity
        confidence = 1.0
        if len(intermediate_nodes) > 3:
            confidence = max(0.5, 1.0 - (len(intermediate_nodes) - 3) * 0.1)

        taint_path = TaintPath(
            source_node=source_node,
            sink_node=sink_node,
            intermediate_nodes=intermediate_nodes,
            tainted_variables=[tainted_var],
            confidence=confidence,
        )

        self.taint_paths.append(taint_path)

        if self.debug:
            logger.debug(
                f"[CallChain] Created taint path: {source_node.function_name} -> {sink_node.function_name} (confidence: {confidence:.2f})"
            )

        return taint_path

    def _extract_arguments(self, node: ast.Call) -> List[str]:
        """Extract argument names from function call."""
        arguments = []
        for arg in node.args:
            if isinstance(arg, ast.Name):
                arguments.append(arg.id)
            elif isinstance(arg, ast.Constant):
                arguments.append(str(arg.value))
            elif isinstance(arg, ast.Attribute):
                arguments.append(self._get_attribute_name(arg))
            else:
                arguments.append(f"<{type(arg).__name__}>")
        return arguments

    def _get_attribute_name(self, node: ast.Attribute) -> str:
        """Get full attribute name (e.g., 'os.system')."""
        if isinstance(node.value, ast.Name):
            return f"{node.value.id}.{node.attr}"
        elif isinstance(node.value, ast.Attribute):
            return f"{self._get_attribute_name(node.value)}.{node.attr}"
        else:
            return node.attr

    def get_detailed_paths(self) -> List[Dict[str, Any]]:
        """Get detailed information about all taint paths."""
        detailed_paths = []

        for path in self.taint_paths:
            path_info = {
                "source": {
                    "function": path.source_node.function_name,
                    "line": path.source_node.line_number,
                    "column": path.source_node.column,
                    "type": path.source_node.node_type,
                    "arguments": path.source_node.arguments,
                },
                "sink": {
                    "function": path.sink_node.function_name,
                    "line": path.sink_node.line_number,
                    "column": path.sink_node.column,
                    "type": path.sink_node.node_type,
                    "arguments": path.sink_node.arguments,
                },
                "path": [
                    {
                        "function": node.function_name,
                        "line": node.line_number,
                        "column": node.column,
                        "type": node.node_type,
                        "variable": node.variable_name,
                    }
                    for node in path.intermediate_nodes
                ],
                "tainted_variables": path.tainted_variables,
                "confidence": path.confidence,
                "path_length": path.path_length,
                "complexity": "low"
                if path.path_length <= 3
                else "medium"
                if path.path_length <= 6
                else "high",
            }
            detailed_paths.append(path_info)

        return detailed_paths

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of call chain analysis."""
        return {
            "total_paths": len(self.taint_paths),
            "average_path_length": sum(p.path_length for p in self.taint_paths)
            / len(self.taint_paths)
            if self.taint_paths
            else 0,
            "high_confidence_paths": len(
                [p for p in self.taint_paths if p.confidence > 0.8]
            ),
            "complex_paths": len([p for p in self.taint_paths if p.path_length > 6]),
            "tracked_variables": len(self.variable_assignments),
            "tracked_functions": len(self.function_calls),
            "data_flow_edges": len(self.data_flow_edges),
        }
