"""
Call chain builder for flow analysis.

This module provides functionality for building call chains and
detecting vulnerabilities in the refactored architecture.
"""

from typing import Any, Dict, List, Optional

from lanalyzer.logger import debug

from ..core.visitor import TaintAnalysisVisitor
from .analyzer import FlowAnalyzer


class CallChainBuilder:
    """
    Builder for constructing call chains and vulnerability paths.

    This class replaces the complex call chain building logic
    with a simplified, more maintainable implementation.
    """

    def __init__(self, tracker, debug_mode: bool = False):
        """
        Initialize the call chain builder.

        Args:
            tracker: Parent tracker instance
            debug_mode: Whether to enable debug output
        """
        self.tracker = tracker
        self.debug = debug_mode
        self.flow_analyzer = FlowAnalyzer(tracker, debug_mode)

    def get_detailed_call_chain(
        self,
        visitor: TaintAnalysisVisitor,
        sink_info: Dict[str, Any],
        source_info: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Get detailed call chain from source to sink.

        Args:
            visitor: Visitor instance with analysis results
            sink_info: Information about the sink
            source_info: Information about the source

        Returns:
            List of call chain steps
        """
        call_chain = []

        source_line = source_info.get("line", 0)
        sink_line = sink_info.get("line", 0)

        if self.debug:
            debug(
                f"[CallChainBuilder] Building call chain from line {source_line} to {sink_line}"
            )

        # Add source step
        source_step = self._create_source_step(visitor, source_info)
        if source_step:
            call_chain.append(source_step)

        # Add data flow steps
        data_flow_steps = self.flow_analyzer.analyze_data_flow(
            visitor,
            source_info.get("variable", ""),
            source_line,
            sink_line,
            sink_info.get("args", []),
        )
        call_chain.extend(data_flow_steps)

        # Add control flow steps
        control_flow_steps = self.flow_analyzer.analyze_control_flow(visitor, sink_info)
        call_chain.extend(control_flow_steps)

        # Add sink step
        sink_step = self._create_sink_step(visitor, sink_info)
        if sink_step:
            call_chain.append(sink_step)

        # Sort by line number and remove duplicates
        call_chain = self._deduplicate_and_sort(call_chain)

        if self.debug:
            debug(f"[CallChainBuilder] Built call chain with {len(call_chain)} steps")

        return call_chain

    def _create_source_step(
        self, visitor: TaintAnalysisVisitor, source_info: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Create a call chain step for the source."""
        line = source_info.get("line", 0)
        name = source_info.get("name", "Unknown")

        if not visitor.source_lines or line <= 0 or line > len(visitor.source_lines):
            return None

        statement = visitor.source_lines[line - 1].strip()

        return {
            "function": f"Source: {name}",
            "file": visitor.file_path,
            "line": line,
            "statement": statement,
            "type": "source",
            "description": f"Taint source {name} at line {line}",
        }

    def _create_sink_step(
        self, visitor: TaintAnalysisVisitor, sink_info: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Create a call chain step for the sink."""
        line = sink_info.get("line", 0)
        name = sink_info.get("name", "Unknown")

        if not visitor.source_lines or line <= 0 or line > len(visitor.source_lines):
            return None

        statement = visitor.source_lines[line - 1].strip()

        return {
            "function": f"Sink: {name}",
            "file": visitor.file_path,
            "line": line,
            "statement": statement,
            "type": "sink",
            "description": f"Taint sink {name} at line {line}",
        }

    def _deduplicate_and_sort(
        self, call_chain: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Remove duplicates and sort call chain by line number."""
        seen_lines = set()
        unique_steps = []

        for step in call_chain:
            line = step.get("line", 0)
            if line not in seen_lines:
                seen_lines.add(line)
                unique_steps.append(step)

        # Sort by line number
        return sorted(unique_steps, key=lambda x: x.get("line", 0))

    def build_vulnerability_chain(
        self,
        visitor: TaintAnalysisVisitor,
        vulnerability: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Build a complete vulnerability chain with call and data flow information.

        Args:
            visitor: Visitor instance
            vulnerability: Vulnerability information

        Returns:
            Enhanced vulnerability with call chain
        """
        source_info = vulnerability.get("source", {})
        sink_info = vulnerability.get("sink", {})

        # Get detailed call chain
        call_chain = self.get_detailed_call_chain(visitor, sink_info, source_info)

        # Enhance vulnerability with call chain
        enhanced_vulnerability = vulnerability.copy()
        enhanced_vulnerability["call_chain"] = call_chain
        enhanced_vulnerability["chain_length"] = len(call_chain)

        return enhanced_vulnerability

    def analyze_cross_function_flow(
        self,
        visitor: TaintAnalysisVisitor,
        source_func: str,
        sink_func: str,
    ) -> List[Dict[str, Any]]:
        """
        Analyze data flow across function boundaries.

        Args:
            visitor: Visitor instance
            source_func: Source function name
            sink_func: Sink function name

        Returns:
            List of cross-function flow steps
        """
        # This is a simplified implementation
        # In a full implementation, this would analyze function calls
        # and parameter passing between functions

        cross_function_steps = []

        # Find function calls between source and sink functions
        for call in visitor.call_locations:
            call_name = call.get("name", "")
            if call_name in [source_func, sink_func]:
                step = {
                    "function": f"Function call: {call_name}",
                    "file": visitor.file_path,
                    "line": call.get("line", 0),
                    "type": "function_call",
                    "description": f"Call to {call_name}",
                }
                cross_function_steps.append(step)

        return cross_function_steps
