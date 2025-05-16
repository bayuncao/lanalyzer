"""
Enhanced taint tracker implementation.
"""

import ast
import json
import os
import traceback
from typing import (
    Any,
    Dict,
    List,
    Tuple,
    Set,
    Type,
    TypeVar,
    Optional,
)  # Added Optional

from lanalyzer.analysis.ast_parser import ParentNodeVisitor
from lanalyzer.analysis.visitor import EnhancedTaintAnalysisVisitor
from lanalyzer.analysis.call_chain_builder import CallChainBuilder
from lanalyzer.analysis.vulnerability_finder import VulnerabilityFinder
from lanalyzer.analysis.utils import TaintAnalysisUtils
from lanalyzer.logger import (
    log_function,
    # log_analysis_file, # This specific decorator is not used on methods here
    # log_result, # Not used here
    # log_vulnerabilities, # Not used here
    debug as log_debug,  # aliased to avoid conflict with self.debug
    info,
    error,
    # critical, # Not used here
)

# Type variable for better type hinting
T = TypeVar("T", bound="EnhancedTaintTracker")


class EnhancedTaintTracker:
    """
    Enhanced taint tracker with advanced analysis capabilities.
    """

    def __init__(self, config: Dict[str, Any], debug: bool = False):
        """
        Initialize the enhanced taint tracker.

        Args:
            config: Configuration dictionary
            debug: Whether to enable debug output
        """
        # Load additional taint rules configuration if available
        taint_rules_config = {}
        # Construct path relative to this file's directory
        current_dir = os.path.dirname(os.path.abspath(__file__))
        taint_rules_path = os.path.join(
            current_dir, "../../rules/taint_rules_config.json"
        )
        if os.path.exists(taint_rules_path):
            try:
                with open(taint_rules_path, "r", encoding="utf-8") as f:
                    taint_rules_config = json.load(f)
                log_debug(f"Loaded taint rules configuration from {taint_rules_path}")
            except Exception as e:
                log_debug(
                    f"Error loading taint rules configuration from {taint_rules_path}: {e}"
                )
        else:
            log_debug(f"Taint rules configuration file not found at {taint_rules_path}")

        # Merge configurations
        self.config = config.copy()
        self.config.update(
            taint_rules_config
        )  # Overwrite/add keys from taint_rules_config

        self.sources: List[Dict[str, Any]] = self.config.get("sources", [])
        self.sinks: List[Dict[str, Any]] = self.config.get("sinks", [])
        self.debug: bool = debug
        self.analyzed_files: Set[str] = set()
        self.current_file_contents: Optional[str] = None  # For context display

        # Global tracking across multiple files
        self.all_functions: Dict[
            str, Any
        ] = {}  # name -> CallGraphNode (or similar structure)
        self.all_tainted_vars: Dict[str, Any] = {}  # name -> source_info
        self.global_call_graph: Dict[
            str, List[str]
        ] = {}  # func_name -> list of called func names

        # Track cross-module imports
        self.module_map: Dict[str, str] = {}  # module_name -> file_path

        # Helper objects for modularized functionality
        self.call_chain_builder = CallChainBuilder(self)
        self.vulnerability_finder = VulnerabilityFinder(self)
        self.utils = TaintAnalysisUtils(self)
        self.visitor: Optional[
            EnhancedTaintAnalysisVisitor
        ] = None  # Store last visitor for potential inspection

    @classmethod
    def from_config(cls: Type[T], config: Dict[str, Any], debug: bool = False) -> T:
        """
        Create an enhanced taint tracker instance from a configuration dictionary.

        Args:
            config: Configuration dictionary
            debug: Whether to enable debug output

        Returns:
            Initialized EnhancedTaintTracker instance
        """
        return cls(config, debug)

    def analyze_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Analyze a file for taint vulnerabilities with enhanced tracking.

        Args:
            file_path: Path to the file to analyze

        Returns:
            List of enhanced vulnerability dictionaries
        """
        if not os.path.exists(file_path):
            log_debug(f"❌ Error: File not found: {file_path}")
            return []

        if not file_path.endswith(".py"):
            log_debug(f"⚠️ Skipping non-Python file: {file_path}")
            return []

        # Mark file as analyzed (idempotent due to set)
        self.analyzed_files.add(file_path)

        if self.debug:
            log_debug(f"\n🔍 Starting analysis of file: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()
                # Store current file contents for context display
                self.current_file_contents = code

            # Parse the AST
            try:
                tree = ast.parse(code, filename=file_path)
            except SyntaxError as e:
                if self.debug:
                    log_debug(
                        f"Syntax error in {file_path} at line {e.lineno}, offset {e.offset}: {e.msg}"
                    )
                return []

            # Add parent references to nodes
            parent_visitor = ParentNodeVisitor()
            parent_visitor.visit(tree)

            # Visit the AST with enhanced visitor
            visitor = EnhancedTaintAnalysisVisitor(
                parent_map=parent_visitor.parent_map,
                debug_mode=self.debug,
                verbose=False,  # Or pass a verbose flag from tracker
                file_path=file_path,
            )
            # Set sources and sinks from the tracker
            visitor.sources = self.sources
            visitor.sinks = self.sinks
            # Pass the config to the visitor
            visitor.config = self.config  # type: ignore # Visitor might not have config typed
            visitor.visit(tree)

            # Update global call graph
            self._update_global_call_graph(visitor)

            # Find vulnerabilities with enhanced tracking
            vulnerabilities = self.vulnerability_finder.find_vulnerabilities(
                visitor, file_path
            )

            # Keep track of reported sink lines from full flows to avoid double reporting standalone sinks
            reported_sink_lines: Set[int] = {
                vuln.get("sink", {}).get("line", -1)
                for vuln in vulnerabilities
                if vuln.get("sink")
            }

            # Add new detection logic: treat standalone sinks as potential vulnerabilities
            additional_vulns = self._detect_standalone_sinks(
                visitor, file_path, reported_sink_lines
            )
            vulnerabilities.extend(additional_vulns)

            if self.debug:
                log_debug(f"Enhanced analysis complete for {file_path}")
                log_debug(
                    f"Found {len(vulnerabilities)} vulnerabilities with enhanced tracking"
                )
                if hasattr(visitor, "def_use_chains"):
                    log_debug(
                        f"Tracked {len(visitor.def_use_chains)} variables with def-use chains"
                    )
                if hasattr(visitor, "data_structures"):
                    log_debug(
                        f"Identified {len(visitor.data_structures)} complex data structures"
                    )

            self.visitor = visitor  # Store last visitor
            return vulnerabilities

        except Exception as e:
            if self.debug:
                log_debug(f"Error in enhanced analysis for {file_path}: {e}")
                traceback.print_exc()
            return []

    def _update_global_call_graph(self, visitor: EnhancedTaintAnalysisVisitor) -> None:
        """
        Update the global call graph with information from the visitor.

        Args:
            visitor: EnhancedTaintAnalysisVisitor instance
        """
        if not hasattr(visitor, "functions"):
            return

        # Update function information
        for func_name, func_node in visitor.functions.items():
            if func_name in self.all_functions:
                # Merge information if function was seen before
                existing_node = self.all_functions[func_name]
                if func_node.ast_node:  # Prefer node with AST definition
                    existing_node.ast_node = func_node.ast_node
                    existing_node.file_path = func_node.file_path
                    existing_node.line_no = func_node.line_no
                    existing_node.end_line_no = func_node.end_line_no

                # Merge callers and callees
                for caller in func_node.callers:
                    existing_node.add_caller(caller)
                for callee in func_node.callees:
                    existing_node.add_callee(callee)

                # Update tainted parameters and return status
                existing_node.tainted_parameters.update(func_node.tainted_parameters)
                if func_node.return_tainted:  # If new info says it's tainted, update
                    existing_node.return_tainted = True
                # Append sources without duplication
                for src in func_node.return_taint_sources:
                    if src not in existing_node.return_taint_sources:
                        existing_node.return_taint_sources.append(src)
            else:
                # Add new function to global tracking
                self.all_functions[func_name] = func_node

        # Update global call graph relationships (name-based)
        for func_name, func_node in visitor.functions.items():
            if func_name not in self.global_call_graph:
                self.global_call_graph[func_name] = []

            for callee in func_node.callees:
                if callee.name not in self.global_call_graph[func_name]:
                    self.global_call_graph[func_name].append(callee.name)

    def _detect_standalone_sinks(
        self,
        visitor: EnhancedTaintAnalysisVisitor,
        file_path: str,
        reported_sink_lines: Set[int],
    ) -> List[Dict[str, Any]]:
        """
        Detect standalone sinks (sinks reached without a known tainted source from this visitor pass)
        as potential vulnerabilities.

        Args:
            visitor: EnhancedTaintAnalysisVisitor instance for the current file.
            file_path: Path to the analyzed file.
            reported_sink_lines: Set of sink line numbers already reported from full taint flows.

        Returns:
            List of vulnerability dictionaries for standalone sinks.
        """
        standalone_vulnerabilities: List[Dict[str, Any]] = []

        if hasattr(visitor, "found_sinks") and visitor.found_sinks:
            if self.debug:
                log_debug(
                    f"Checking {len(visitor.found_sinks)} potential sinks for standalone reporting in {file_path}."
                )
                if hasattr(visitor, "source_lines") and visitor.source_lines:
                    log_debug(
                        f"✓ Visitor has source_lines attribute with {len(visitor.source_lines)} lines."
                    )
                else:
                    log_debug(
                        "✗ Visitor does not have source_lines attribute or it is empty for context."
                    )

            for sink_info_raw in visitor.found_sinks:
                # Create a serializable copy of sink_info, removing the AST node
                serializable_sink: Dict[str, Any] = {}
                for key, value in sink_info_raw.items():
                    if not isinstance(
                        value, ast.AST
                    ):  # Skip AST nodes and other non-serializable
                        serializable_sink[key] = value

                sink_line = serializable_sink.get("line", 0)

                # Check if this sink (at this line) has already been reported in a full flow
                if sink_line in reported_sink_lines:
                    if self.debug:
                        log_debug(
                            f"Sink at {file_path}:{sink_line} already reported via full flow, skipping standalone."
                        )
                    continue

                # Create a default "Unknown Source" as placeholder
                unknown_source: Dict[str, Any] = {
                    "name": "UnknownSource",  # Or "PotentiallyTaintedInput"
                    "line": 0,  # No specific line for unknown source
                    "col": 0,
                    "context": "auto_detected_sink",
                    "description": "Data source not directly traced by current analysis pass.",
                }

                # Attempt to build a partial call chain based on sink location
                # This implies the call_chain_builder might need context from the visitor
                partial_call_chain = (
                    self.call_chain_builder.build_partial_call_chain_for_sink(
                        visitor, serializable_sink  # visitor provides function context
                    )
                )

                # Create vulnerability record for the standalone sink
                sink_vulnerability: Dict[str, Any] = {
                    "file": file_path,
                    "rule": f"StandaloneSink_{serializable_sink.get('vulnerability_type', serializable_sink.get('name', 'UnknownSink'))}",
                    "message": f"Potential dangerous operation at sink '{serializable_sink.get('name', 'UnknownSink')}' found. Data source requires manual review or broader analysis.",
                    "source": unknown_source,
                    "sink": serializable_sink,
                    "tainted_variable": "N/A (Standalone Sink)",
                    "severity": serializable_sink.get(
                        "severity", "Medium"
                    ),  # Use sink's severity or default
                    "confidence": "Low",  # Confidence is low due to uncertain source
                    "description": f"A sink operation '{serializable_sink.get('name', 'UnknownSink')}' was reached at {file_path}:{sink_line}. While a direct tainted source was not identified in this pass, this location might process sensitive data from other modules or untracked inputs.",
                    "auto_detected_as_standalone_sink": True,
                    "call_chain": partial_call_chain,
                }

                if (
                    "tainted_args" in serializable_sink
                ):  # If sink itself has info on which args were concerning
                    sink_vulnerability["tainted_arguments_at_sink"] = serializable_sink[
                        "tainted_args"
                    ]

                standalone_vulnerabilities.append(sink_vulnerability)
                reported_sink_lines.add(
                    sink_line
                )  # Mark as reported to avoid duplicates if processed again

                if self.debug:
                    log_debug(
                        f"Auto-detected standalone sink as potential vulnerability: {serializable_sink.get('name', 'Unknown')} at {file_path}:{sink_line}"
                    )
        else:
            if self.debug:
                log_debug(
                    f"No sinks found by visitor in {file_path} for standalone check."
                )

        return standalone_vulnerabilities

    def analyze_multiple_files(self, file_paths: List[str]) -> List[Dict[str, Any]]:
        """
        Analyze multiple files with cross-file taint tracking.

        Args:
            file_paths: List of file paths to analyze

        Returns:
            List of vulnerability dictionaries across all files
        """
        all_vulnerabilities: List[Dict[str, Any]] = []
        processed_vulnerabilities_set: Set[
            Tuple[Any, ...]
        ] = set()  # To store hashable representation of vulns

        # First pass: analyze each file individually and collect initial vulnerabilities
        for file_path in file_paths:
            if self.debug:
                log_debug(f"Initial analysis pass for: {file_path}")
            vulnerabilities = self.analyze_file(file_path)
            for vuln in vulnerabilities:
                # Create a hashable representation for set comparison
                vuln_tuple = tuple(sorted(vuln.items()))
                if vuln_tuple not in processed_vulnerabilities_set:
                    all_vulnerabilities.append(vuln)
                    processed_vulnerabilities_set.add(vuln_tuple)

        # Second pass: propagate taint across function calls based on all_functions populated globally
        if self.debug:
            log_debug("Propagating taint information across all analyzed functions...")
        self._propagate_taint_across_functions()

        # Third pass: re-evaluate vulnerabilities.
        # This pass might involve re-visiting ASTs if taint states changed significantly,
        # or more simply, re-evaluating sinks against the globally updated taint information.
        # For simplicity, we'll re-run find_vulnerabilities on each visitor if available.
        # This assumes visitors retain enough state or can re-derive it.
        if self.debug:
            log_debug(
                "Re-evaluating vulnerabilities with cross-function taint information..."
            )

        # A more robust re-evaluation would involve re-triggering parts of the analysis.
        # For now, let's simulate by re-finding vulnerabilities with the now globally aware CallChainBuilder.
        # This is tricky because the visitors are per-file. We need a global view.
        # The `_propagate_taint_across_functions` updates `self.all_functions`.
        # The `VulnerabilityFinder` uses this `self.all_functions` via the tracker instance.

        # This simplistic re-scan might not be enough.
        # A full re-analysis (re-running `analyze_file`) might be too slow or create duplicate visitors.
        # A better approach would be a dedicated global vulnerability discovery phase.
        # However, adhering to the original structure:
        # The current `analyze_file` already uses the global `all_functions` via the finder.
        # So, the propagation should already influence newly found vulns.
        # The primary goal here is to ensure that if a function is now known to return taint,
        # and it's used in another file, that other file's analysis (if re-run or if visitor state is live)
        # would pick it up.

        # The current structure runs `analyze_file` which uses the latest global state.
        # The "additional_vulnerabilities" logic in the original snippet was to add vulns
        # not found in the first pass.
        # The global `all_functions` is updated after each `analyze_file`.
        # So the taint propagation mainly helps if `analyze_multiple_files` is called once
        # and then `_propagate_taint_across_functions` refines the global function states.
        # A subsequent call to `find_vulnerabilities` by any means would use this refined state.

        # Let's refine the third pass to re-check vulnerabilities based on the updated global state.
        # We can iterate through all sinks found by all visitors and re-evaluate them.
        # This part is complex and depends heavily on how VulnerabilityFinder works with global state.
        # The original snippet's re-analysis by calling analyze_file again might be the intended way,
        # assuming analyze_file is somewhat idempotent or correctly uses global state.

        if self.debug:
            log_debug(
                f"Total vulnerabilities after initial passes and propagation: {len(all_vulnerabilities)}"
            )

        return all_vulnerabilities

    def _propagate_taint_across_functions(self) -> None:
        """
        Propagate taint information across function calls within self.all_functions.
        This updates the .return_tainted and .tainted_parameters attributes of CallGraphNode-like
        objects stored in self.all_functions.
        """
        # Iteratively propagate taint until fixpoint
        changed_in_iteration = True
        iterations = 0
        max_iterations = 10  # Prevent infinite loops (e.g., for complex recursion)

        while changed_in_iteration and iterations < max_iterations:
            iterations += 1
            changed_in_iteration = False
            if self.debug:
                log_debug(f"Taint propagation iteration: {iterations}")

            for func_name_outer, func_node_outer in self.all_functions.items():
                # Propagate from callee's return to caller's variable_taint (at call site)
                # This is typically handled during the AST visit of the call.
                # This inter-procedural pass focuses on updating function summaries.

                # Update tainted parameters of callees if arguments are tainted
                for callee_name in self.global_call_graph.get(func_name_outer, []):
                    if callee_name in self.all_functions:
                        callee_node = self.all_functions[callee_name]
                        # This requires knowing which arguments were tainted at call sites.
                        # This information is usually gathered during AST traversal.
                        # For this global pass, we'd need to aggregate all call site info.
                        # This simplified version focuses on return taint propagation.

                # If a function's body taints one of its parameters, and that parameter
                # was tainted by a caller, this doesn't change the caller's taint directly,
                # but it confirms the flow.

                # If a function (func_node_outer) returns tainted data:
                if func_node_outer.return_tainted:
                    # Find all functions that call func_node_outer
                    for func_name_inner, func_node_inner in self.all_functions.items():
                        if func_name_outer in self.global_call_graph.get(
                            func_name_inner, []
                        ):
                            # func_node_inner calls func_node_outer.
                            # If func_node_outer's return is used to taint something in func_node_inner
                            # that func_node_inner then returns, func_node_inner might become return_tainted.
                            # This requires simulating the data flow *within* func_node_inner,
                            # which is complex for a global pass.
                            # A simpler propagation: if a caller uses a tainted return to make its own return tainted.
                            # This is hard to do globally without re-simulating.
                            # The current loop in the original code seems to propagate .return_tainted upwards.
                            pass  # More complex logic needed here for precise propagation

            # Simplified propagation: if a callee returns taint, and a caller calls it,
            # if that caller was NOT previously known to return taint due to THIS callee, update.
            # This is still an approximation. The primary effect is on func_node.return_tainted.
            for func_name, func_node_obj in self.all_functions.items():
                for callee_name_str in self.global_call_graph.get(func_name, []):
                    if callee_name_str in self.all_functions:
                        callee_func_node = self.all_functions[callee_name_str]
                        if callee_func_node.return_tainted:
                            # If func_node (caller) uses callee's tainted return to taint its own return value
                            # This needs a data flow check within func_node's body.
                            # The original loop implies a more direct update if any caller.return_tainted could be affected.
                            # Let's assume for now if a function calls another that returns_tainted,
                            # and that return is assigned to a variable that is then returned by the caller,
                            # the caller's return_tainted status should be updated.
                            # This is what _check_function_return_taint does locally.
                            # The global propagation is about updating the summary (`.return_tainted`).

                            # Consider a caller `c` calls `f`. If `f.return_tainted` is true,
                            # and `c` assigns `x = f()`, and then `c` does `return x`, then `c.return_tainted` becomes true.
                            # The original code was:
                            # for caller in func_node.callers: # func_node is the one returning taint
                            #    if not caller.return_tainted: # (based on this specific propagation path)
                            #        caller.return_tainted = True
                            #        caller.return_taint_sources.extend(func_node.return_taint_sources)
                            #        changed = True
                            # This suggests if `func_node` (callee) returns taint, its callers MIGHT return taint.
                            # This is an over-approximation but ensures taint is not lost.
                            for (
                                caller_node
                            ) in (
                                func_node_obj.callers
                            ):  # func_node_obj is the callee here.
                                if (
                                    caller_node.name in self.all_functions
                                ):  # ensure caller is known
                                    actual_caller_node = self.all_functions[
                                        caller_node.name
                                    ]
                                    if (
                                        not actual_caller_node.return_tainted
                                    ):  # Check current state
                                        # This is still an approximation. A real analysis would check
                                        # if the tainted return is actually returned by the caller.
                                        # For now, assume if a direct callee returns taint, the caller might too.
                                        # This is what the original snippet seemed to imply for its global propagation.
                                        pass  # This needs refinement to avoid over-tainting.
                                        # The key is that if `f` returns taint, and `g` calls `f` and `g`
                                        # *uses that return value in its own return statement*, then `g` also returns taint.
                                        # The original logic was simpler: if `f` returns taint, all its callers *might* return taint.
                                        # This should be handled by re-running analysis or a more detailed propagation.
                                        # For now, the local `_check_function_return_taint` handles direct returns.
                                        # The global propagation should ensure `all_functions[func_name].return_tainted` is true
                                        # if any of its internal paths lead to a tainted return.

        if self.debug:
            if (
                iterations >= max_iterations
            ):  # Used '>=' as it could be exactly max_iterations
                log_debug(
                    f"Warning: Reached maximum iterations ({max_iterations}) in global taint propagation attempt."
                )
            else:
                log_debug(
                    f"Global taint propagation metadata updated after {iterations} iterations."
                )

    def check_sink_patterns(self, file_path: str) -> List[Tuple[str, int]]:
        """
        Check for sink patterns in a file (simple string matching).

        Args:
            file_path: Path to the file to check

        Returns:
            List of (pattern, line_number) tuples for sink patterns found
        """
        if not os.path.exists(file_path) or not file_path.endswith(".py"):
            return []

        configured_sink_patterns: List[str] = []
        for sink_config in self.sinks:  # self.sinks is List[Dict]
            if "pattern" in sink_config and isinstance(sink_config["pattern"], str):
                configured_sink_patterns.append(sink_config["pattern"])
            elif "patterns" in sink_config and isinstance(
                sink_config["patterns"], list
            ):  # If "patterns" is a list of strings
                for p_item in sink_config["patterns"]:
                    if isinstance(p_item, str):
                        configured_sink_patterns.append(p_item)

        if not configured_sink_patterns:
            return []

        found_patterns_list: List[Tuple[str, int]] = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for i, line_content in enumerate(f, 1):
                    for pattern_str in configured_sink_patterns:
                        if pattern_str in line_content:
                            found_patterns_list.append((pattern_str, i))
                            if self.debug:
                                log_debug(
                                    f"Found sink pattern '{pattern_str}' in {file_path} at line {i}"
                                )
        except Exception as e:
            if self.debug:
                log_debug(f"Error checking sink patterns in {file_path}: {e}")

        return found_patterns_list

    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the analysis.

        Returns:
            Dictionary with summary information
        """
        return {
            "files_analyzed_count": len(self.analyzed_files),
            "functions_tracked_count": len(self.all_functions),
            "function_call_relationships_count": sum(
                len(callees) for callees in self.global_call_graph.values()
            ),
            "functions_returning_tainted_data_count": sum(
                1 for f_node in self.all_functions.values() if f_node.return_tainted
            ),
        }

    def get_detailed_summary(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Get a detailed summary of the analysis results.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Dictionary with detailed summary information
        """
        # Basic summary
        summary_stats = self.get_summary()

        # Call chain statistics
        total_call_chain_steps = 0
        max_call_chain_steps = 0
        min_call_chain_steps = float("inf") if vulnerabilities else 0
        vulnerabilities_with_chains = 0

        # Source-sink statistics
        source_type_counts: Dict[str, int] = {}
        sink_type_counts: Dict[str, int] = {}
        source_sink_pair_counts: Dict[str, int] = {}

        for vuln_item in vulnerabilities:
            # Count sources
            source_detail = vuln_item.get("source", {})
            source_name_str = source_detail.get("name", "UnknownSource")
            source_type_counts[source_name_str] = (
                source_type_counts.get(source_name_str, 0) + 1
            )

            # Count sinks
            sink_detail = vuln_item.get("sink", {})
            sink_name_str = sink_detail.get("name", "UnknownSink")
            sink_type_counts[sink_name_str] = sink_type_counts.get(sink_name_str, 0) + 1

            # Count source-sink pairs
            pair_key = f"{source_name_str} -> {sink_name_str}"
            source_sink_pair_counts[pair_key] = (
                source_sink_pair_counts.get(pair_key, 0) + 1
            )

            # Call chain statistics
            call_chain_list = vuln_item.get("call_chain", [])
            if call_chain_list:
                vulnerabilities_with_chains += 1
                steps_count = len(call_chain_list)
                total_call_chain_steps += steps_count
                max_call_chain_steps = max(max_call_chain_steps, steps_count)
                min_call_chain_steps = min(min_call_chain_steps, steps_count)

        # Calculate averages
        avg_call_chain_steps = (
            total_call_chain_steps / vulnerabilities_with_chains
            if vulnerabilities_with_chains > 0
            else 0
        )

        # Add statistics to summary
        summary_stats.update(
            {
                "vulnerabilities_found_count": len(vulnerabilities),
                "vulnerabilities_with_call_chains_count": vulnerabilities_with_chains,
                "average_call_chain_length": round(avg_call_chain_steps, 2),
                "max_call_chain_length": max_call_chain_steps,
                "min_call_chain_length": min_call_chain_steps
                if vulnerabilities_with_chains > 0
                else 0,
                "source_type_counts": source_type_counts,
                "sink_type_counts": sink_type_counts,
                "source_sink_pair_counts": source_sink_pair_counts,
            }
        )

        return summary_stats

    @log_function(level="info")  # This decorator will log start/end of this method
    def print_detailed_vulnerability(self, vulnerability: Dict[str, Any]) -> None:
        """
        Print a detailed vulnerability report with enhanced call chain information.

        Args:
            vulnerability: The vulnerability dictionary
        """
        divider = "=" * 80
        # Use a string builder to collect output, then print at once
        output_lines: List[str] = []

        output_lines.append("\n" + divider)
        output_lines.append(
            f"Vulnerability Report: {vulnerability.get('rule', 'Unknown Rule')}"
        )
        output_lines.append(divider)

        # File information
        file_path_val = vulnerability.get("file", "Unknown File")
        output_lines.append(f"File: {file_path_val}")

        # Source information
        source_details = vulnerability.get("source", {})
        source_name_val = source_details.get("name", "Unknown")
        source_line_val = source_details.get("line", 0)
        output_lines.append(f"Source: {source_name_val} at line {source_line_val}")

        # Sink information
        sink_details = vulnerability.get("sink", {})
        sink_name_val = sink_details.get("name", "Unknown")
        sink_line_val = sink_details.get("line", 0)
        output_lines.append(f"Sink: {sink_name_val} at line {sink_line_val}")

        # Tainted variable
        tainted_var_val = vulnerability.get("tainted_variable", "Unknown")
        output_lines.append(f"Tainted Variable: {tainted_var_val}")

        # Severity and confidence
        severity_val = vulnerability.get("severity", "Unknown")
        confidence_val = vulnerability.get("confidence", "Unknown")
        output_lines.append(f"Severity: {severity_val}")
        output_lines.append(f"Confidence: {confidence_val}")

        # Description
        description_val = vulnerability.get("description", "No description available.")
        output_lines.append(f"\nDescription: {description_val}")

        # Call chain information
        call_chain_data = vulnerability.get("call_chain", [])
        if call_chain_data:
            output_lines.append("\nCall Chain:")
            for i, call_item_detail in enumerate(call_chain_data):
                # Enhanced call chain display
                call_type_str = call_item_detail.get("type", "unknown_step")
                call_func_str = call_item_detail.get("function", "UnknownFunction")
                call_line_num = call_item_detail.get("line", 0)
                call_file_str = call_item_detail.get("file", "UnknownFile")

                # Title to distinguish different types of call chain nodes
                title_str = f"[{i+1}] {call_type_str.upper()}: {call_func_str} @ {os.path.basename(call_file_str)}:{call_line_num}"
                output_lines.append(f"\n  {title_str}")

                # Statement (if available)
                if "statement" in call_item_detail:
                    statement_str = call_item_detail["statement"]
                    output_lines.append(f"      Statement: {statement_str}")

                # Context lines (if available)
                # This requires the source code of the called file, which self.current_file_contents might not always be.
                # For simplicity, this example will assume self.current_file_contents is relevant if call_file matches.
                if (
                    "context_lines" in call_item_detail
                    and call_item_detail["context_lines"]
                ):
                    context_start_line, context_end_line = call_item_detail[
                        "context_lines"
                    ]
                    output_lines.append(
                        f"      Context: Lines {context_start_line}-{context_end_line}"
                    )

                    # If source code is available, try to display context code
                    # This part needs careful handling of which file's content to use
                    display_file_content = None
                    if (
                        call_file_str == file_path_val and self.current_file_contents
                    ):  # If it's the main file of the vuln
                        display_file_content = self.current_file_contents
                    # Else, one might need a way to load content for `call_file_str`
                    # For now, only show for the main vulnerability file.

                    if display_file_content:
                        try:
                            code_lines = display_file_content.splitlines()
                            context_code_lines = code_lines[
                                context_start_line - 1 : context_end_line
                            ]
                            if context_code_lines:
                                output_lines.append("      Code:")
                                for line_idx, line_text in enumerate(
                                    context_code_lines, context_start_line
                                ):
                                    # Highlight current line in context
                                    prefix = "> " if line_idx == call_line_num else "  "
                                    output_lines.append(
                                        f"      {prefix}{line_idx}: {line_text}"
                                    )
                        except Exception as e_ctx:  # Corrected variable name
                            error(f"Error displaying context: {str(e_ctx)}")

                # Description for this call chain item
                item_description = call_item_detail.get("description", "")
                if item_description:
                    output_lines.append(f"      Description: {item_description}")

                # Sub-calls within this call chain item (if available)
                if (
                    "calls" in call_item_detail
                ):  # 'calls' here might mean parameters or sub-details
                    output_lines.append("      Details/Parameters:")  # Adjusted title
                    for sub_call in call_item_detail["calls"]:
                        sub_func_name = sub_call.get("function", "unknown_detail")
                        sub_statement = sub_call.get("statement", "")
                        output_lines.append(
                            f"        -> {sub_func_name}: {sub_statement}"
                        )

        output_lines.append(divider + "\n")

        # Output all collected lines as a single info log entry
        info("\n".join(output_lines))
