"""
Utility functions for call chain analysis.
"""

import re
from typing import Any, Dict, List, Set

from lanalyzer.logger import debug


class ChainUtils:
    """Utility functions for call chain building and analysis."""

    def __init__(self, builder):
        """Initialize with reference to parent builder."""
        self.builder = builder
        self.tracker = builder.tracker
        self.debug = builder.debug

    def reorder_call_chain_by_data_flow(
        self, call_chain: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Reorder call chain based on data flow dependencies.
        Ensures the call chain accurately reflects how data flows from source to sink,
        even if steps occur in different functions.

        Args:
            call_chain: Original call chain

        Returns:
            Reordered call chain
        """
        if not call_chain:
            return []

        # Categorize nodes by type
        sources = []
        data_flows = []
        function_calls = []
        sink_containers = []
        sinks = []
        others = []

        for node in call_chain:
            node_type = node.get("type", "")
            if node_type == "source":
                sources.append(node)
            elif node_type == "data_flow":
                data_flows.append(node)
            elif node_type == "function_call":
                function_calls.append(node)
            elif node_type == "sink_container":
                sink_containers.append(node)
            elif node_type == "sink":
                sinks.append(node)
            else:
                others.append(node)

        # Sort source nodes and flow nodes by line number
        sources.sort(key=lambda x: x.get("line", 0))
        data_flows.sort(key=lambda x: x.get("line", 0))
        function_calls.sort(key=lambda x: x.get("line", 0))

        # Construct new call chain
        reordered_chain = []

        # 1. Add source nodes
        for node in sources:
            reordered_chain.append(node)

        # 2. Add data flow nodes
        for node in data_flows:
            reordered_chain.append(node)

        # 3. Add function call point nodes - arranged in call order
        for node in function_calls:
            reordered_chain.append(node)

        # 4. If there are other nodes, maintain their relative order
        for node in others:
            reordered_chain.append(node)

        # 5. Add container nodes containing sinks
        for node in sink_containers:
            reordered_chain.append(node)

        # 6. Finally add sink nodes
        for node in sinks:
            reordered_chain.append(node)

        # Ensure uniqueness of each node (prevent duplicates)
        seen = set()
        final_chain = []
        for node in reordered_chain:
            node_id = f"{node.get('line', 0)}:{node.get('statement', '')}"
            if node_id not in seen:
                seen.add(node_id)
                final_chain.append(node)

        return final_chain

    def find_callers(
        self, func_name: str, reverse_call_graph: Dict[str, List[str]], max_depth: int
    ) -> Set[str]:
        """
        Use BFS to find all functions that call the specified function.

        Args:
            func_name: Name of the function to find callers for
            reverse_call_graph: Reverse call graph
            max_depth: Maximum search depth

        Returns:
            Set of function names that call this function
        """
        callers = set()
        visited = {func_name}
        queue = [(func_name, 0)]

        while queue:
            current, depth = queue.pop(0)

            if depth >= max_depth:
                continue

            current_callers = reverse_call_graph.get(current, [])

            for caller in current_callers:
                callers.add(caller)

                if caller not in visited:
                    visited.add(caller)
                    queue.append((caller, depth + 1))

        return callers

    def get_patterns_from_config(self, pattern_type: str) -> List[str]:
        """
        Get patterns of the specified type from the configuration file

        Args:
            pattern_type: 'sources', 'sinks', or 'sanitizers'

        Returns:
            List of patterns
        """
        patterns = []
        if not hasattr(self.tracker, "config"):
            if self.debug:
                debug("[DEBUG] No configuration found in tracker")
            return patterns

        config = self.tracker.config

        if not isinstance(config, dict):
            if self.debug:
                debug("[DEBUG] Configuration is not a dictionary")
            return patterns

        if pattern_type in config and isinstance(config[pattern_type], list):
            for item in config[pattern_type]:
                if (
                    isinstance(item, dict)
                    and "patterns" in item
                    and isinstance(item["patterns"], list)
                ):
                    patterns.extend(item["patterns"])

        if self.debug:
            debug(f"[DEBUG] Extracted {len(patterns)} patterns for {pattern_type}")

        return patterns

    def extract_sink_parameters(self, sink_code: str) -> List[str]:
        """
        Extract parameter expressions based on configured sink patterns

        Args:
            sink_code: Sink code line

        Returns:
            List of parameter expressions
        """
        sink_patterns = self.get_patterns_from_config("sinks")
        sink_arg_expressions = []

        # If no patterns are obtained from configuration, use default pattern
        if not sink_patterns:
            default_pattern = r"(?:pickle|cloudpickle|yaml|json)\.loads\((.*?)\)"
            matches = re.search(default_pattern, sink_code)
            if matches:
                sink_arg_expressions.append(matches.group(1).strip())
            return sink_arg_expressions

        for pattern in sink_patterns:
            # Convert wildcard patterns to regular expressions
            if "*" in pattern:
                regex_pattern = pattern.replace(".", "\\.").replace("*", ".*?")
                # Construct regex to extract parameters
                full_pattern = f"({regex_pattern})\\s*\\((.*?)\\)"
                matches = re.search(full_pattern, sink_code)
                if matches:
                    sink_arg_expressions.append(matches.group(2).strip())
            else:
                # Handle exact match patterns
                full_pattern = f"({re.escape(pattern)})\\s*\\((.*?)\\)"
                matches = re.search(full_pattern, sink_code)
                if matches:
                    sink_arg_expressions.append(matches.group(2).strip())

        return sink_arg_expressions

    def merge_call_chains(
        self,
        data_flow_chain: List[Dict[str, Any]],
        control_flow_chain: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Merge data flow and control flow call chains

        Args:
            data_flow_chain: Data flow call chain
            control_flow_chain: Control flow call chain

        Returns:
            Merged call chain
        """
        if not control_flow_chain:
            return data_flow_chain

        if not data_flow_chain:
            return control_flow_chain

        # Categorize nodes
        entry_points = []
        control_flows = []
        sources = []
        data_flows = []
        sink_containers = []
        sinks = []

        # Extract nodes from control flow chain
        for node in control_flow_chain:
            node_type = node.get("type", "")
            if node_type == "entry_point":
                entry_points.append(node)
            elif node_type == "control_flow":
                control_flows.append(node)
            elif node_type == "sink_container":
                # Check if already exists in data flow chain
                if not any(n.get("type") == "sink_container" for n in data_flow_chain):
                    sink_containers.append(node)

        # Extract nodes from data flow chain
        for node in data_flow_chain:
            node_type = node.get("type", "")
            if node_type == "source":
                sources.append(node)
            elif node_type == "data_flow":
                data_flows.append(node)
            elif node_type == "sink_container":
                sink_containers.append(node)
            elif node_type == "sink":
                sinks.append(node)

        # Remove duplicates and merge in logical order
        merged_chain = []

        # 1. Add entry points
        for node in entry_points:
            merged_chain.append(node)

        # 2. Add control flow nodes
        for node in control_flows:
            if not any(
                n.get("line") == node.get("line")
                and n.get("function") == node.get("function")
                for n in merged_chain
            ):
                merged_chain.append(node)

        # 3. Add source nodes
        for node in sources:
            if not any(
                n.get("line") == node.get("line")
                and n.get("statement") == node.get("statement")
                for n in merged_chain
            ):
                merged_chain.append(node)

        # 4. Add data flow nodes
        for node in data_flows:
            if not any(
                n.get("line") == node.get("line")
                and n.get("statement") == node.get("statement")
                for n in merged_chain
            ):
                merged_chain.append(node)

        # 5. Add sink container nodes (ensure only added once)
        for node in sink_containers:
            if not any(
                n.get("type") == "sink_container"
                and n.get("function") == node.get("function")
                for n in merged_chain
            ):
                merged_chain.append(node)

        # 6. Add sink nodes
        for node in sinks:
            if not any(
                n.get("line") == node.get("line") and n.get("type") == "sink"
                for n in merged_chain
            ):
                merged_chain.append(node)

        # Sort by line number to ensure call chain order is reasonable
        merged_chain.sort(key=lambda x: x.get("line", 0))

        if self.debug:
            debug(
                f"[DEBUG] Merged control flow ({len(control_flow_chain)} nodes) and data flow ({len(data_flow_chain)} nodes) into {len(merged_chain)} nodes"
            )

        return merged_chain
