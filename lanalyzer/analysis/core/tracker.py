"""
Enhanced taint tracker - refactored version.

This module provides the main orchestrator for taint analysis,
consolidating functionality from the original tracker while
simplifying the architecture.
"""

import os
from typing import Any, Dict, List, Optional, Set, Type, TypeVar

from lanalyzer.logger import debug as log_debug

from .ast_processor import ASTProcessor
from .visitor import TaintAnalysisVisitor

T = TypeVar("T", bound="EnhancedTaintTracker")


class EnhancedTaintTracker:
    """
    Enhanced taint tracker for analyzing Python code.

    This class orchestrates the entire taint analysis process,
    from AST parsing to vulnerability detection.
    """

    def __init__(self, config: Dict[str, Any], debug: bool = False):
        """
        Initialize the enhanced taint tracker.

        Args:
            config: Configuration dictionary with sources, sinks, and rules
            debug: Whether to enable debug output
        """
        self.config = config
        self.debug = debug

        # Extract configuration
        self.sources: List[Dict[str, Any]] = config.get("sources", [])
        self.sinks: List[Dict[str, Any]] = config.get("sinks", [])
        self.rules: List[Dict[str, Any]] = config.get("rules", [])

        # Analysis state
        self.analyzed_files: Set[str] = set()
        self.current_file_contents: Optional[str] = None

        # Global tracking across multiple files
        self.all_functions: Dict[str, Any] = {}
        self.all_tainted_vars: Dict[str, Any] = {}
        self.global_call_graph: Dict[str, List[str]] = {}
        self.module_map: Dict[str, str] = {}

        # Import information tracking
        self.all_imports: Dict[str, Dict[str, Any]] = {}  # file_path -> import_info

        # Core components
        self.ast_processor = ASTProcessor(debug)

        # Store last visitor for inspection
        self.visitor: Optional[TaintAnalysisVisitor] = None

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
        Analyze a single Python file for taint vulnerabilities.

        Args:
            file_path: Path to the Python file to analyze

        Returns:
            List of vulnerability dictionaries
        """
        if not os.path.exists(file_path):
            if self.debug:
                log_debug(f"File not found: {file_path}")
            return [], []

        if file_path in self.analyzed_files:
            if self.debug:
                log_debug(f"File already analyzed: {file_path}")
            return [], []

        self.analyzed_files.add(file_path)

        if self.debug:
            log_debug(f"Analyzing file: {file_path}")

        try:
            # Parse the file
            tree, source_lines, parent_map = self.ast_processor.parse_file(file_path)

            if tree is None:
                return [], []

            # Store current file contents for context display
            if source_lines:
                self.current_file_contents = "".join(source_lines)

            # Create and configure visitor
            visitor = TaintAnalysisVisitor(
                parent_map=parent_map,
                debug_mode=self.debug,
                verbose=False,
                file_path=file_path,
                source_lines=source_lines,
            )

            # Configure visitor with sources and sinks
            visitor.classifier.configure(self.sources, self.sinks, self.config)

            # Visit the AST
            visitor.visit(tree)

            # Store visitor for potential inspection
            self.visitor = visitor

            # Update global state
            self._update_global_state(visitor, file_path)

            # Convert vulnerabilities to standard format and extract call chains
            vulnerabilities, call_chains = self._convert_vulnerabilities(visitor)

            if self.debug:
                log_debug(
                    f"Found {len(vulnerabilities)} vulnerabilities and {len(call_chains)} call chains in {file_path}"
                )

            return vulnerabilities, call_chains

        except Exception as e:
            if self.debug:
                log_debug(f"Error analyzing {file_path}: {e}")
                import traceback

                log_debug(traceback.format_exc())
            return [], []

    def analyze_multiple_files(self, file_paths: List[str]) -> List[Dict[str, Any]]:
        """
        Analyze multiple Python files with cross-file taint propagation.

        Args:
            file_paths: List of file paths to analyze

        Returns:
            List of vulnerability dictionaries from all files
        """
        all_vulnerabilities = []
        processed_vulnerabilities_set = set()

        # First pass: analyze each file individually
        for file_path in file_paths:
            if self.debug:
                log_debug(f"Initial analysis pass for: {file_path}")

            vulnerabilities, _ = self.analyze_file(
                file_path
            )  # Ignore call_chains for now

            for vuln in vulnerabilities:
                # Create a hashable representation for deduplication
                vuln_tuple = tuple(sorted(vuln.items()))
                if vuln_tuple not in processed_vulnerabilities_set:
                    all_vulnerabilities.append(vuln)
                    processed_vulnerabilities_set.add(vuln_tuple)

        # Second pass: propagate taint across function calls
        if self.debug:
            log_debug("Propagating taint information across all analyzed functions...")

        self._propagate_taint_across_functions()

        return all_vulnerabilities

    def get_summary(
        self,
        all_call_chains: List[Dict[str, Any]] = None,
        all_vulnerabilities: List[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Get analysis summary statistics.

        Args:
            all_call_chains: Optional list of all call chains from analysis
            all_vulnerabilities: Optional list of all vulnerabilities from analysis

        Returns:
            Dictionary containing analysis summary
        """
        summary = {
            "files_analyzed": len(self.analyzed_files),
            "functions_found": len(self.all_functions),
            "tainted_variables": len(self.all_tainted_vars),
        }

        if self.visitor:
            # Calculate total vulnerabilities from actual output (vulnerabilities + call_chains)
            total_vulnerabilities = 0
            if all_vulnerabilities is not None:
                total_vulnerabilities += len(all_vulnerabilities)
            if all_call_chains is not None:
                total_vulnerabilities += len(all_call_chains)

            # If we don't have the actual output, fall back to visitor count
            if total_vulnerabilities == 0:
                total_vulnerabilities = len(self.visitor.found_vulnerabilities)

            summary.update(
                {
                    "sources_found": len(self.visitor.found_sources),
                    "sinks_found": len(self.visitor.found_sinks),
                    "vulnerabilities_found": total_vulnerabilities,
                }
            )

        # Add import information summary
        if self.all_imports:
            all_stdlib_modules = set()
            all_third_party_modules = set()
            all_imported_functions = set()
            all_imported_classes = set()
            total_imports = 0

            for file_path, import_info in self.all_imports.items():
                all_stdlib_modules.update(
                    import_info.get("standard_library_modules", [])
                )
                all_third_party_modules.update(
                    import_info.get("third_party_modules", [])
                )
                all_imported_functions.update(import_info.get("imported_functions", []))
                all_imported_classes.update(import_info.get("imported_classes", []))
                total_imports += import_info.get("total_imports", 0)

            summary["imports"] = {
                "total_imports": total_imports,
                "unique_stdlib_modules": len(all_stdlib_modules),
                "unique_third_party_modules": len(all_third_party_modules),
                "unique_functions": len(all_imported_functions),
                "unique_classes": len(all_imported_classes),
                "stdlib_modules": sorted(list(all_stdlib_modules)),
                "third_party_modules": sorted(list(all_third_party_modules)),
                "imported_functions": sorted(list(all_imported_functions)),
                "imported_classes": sorted(list(all_imported_classes)),
            }

        # Add call chain analysis summary
        if all_call_chains is not None:
            # Calculate statistics from actual call chains
            total_paths = len(all_call_chains)
            if total_paths > 0:
                path_lengths = [
                    chain.get("path_analysis", {}).get("path_length", 2)
                    for chain in all_call_chains
                ]
                avg_path_length = sum(path_lengths) / len(path_lengths)
                high_confidence_paths = len(
                    [
                        chain
                        for chain in all_call_chains
                        if chain.get("path_analysis", {}).get("confidence", 0) > 0.8
                    ]
                )
                complex_paths = len(
                    [
                        chain
                        for chain in all_call_chains
                        if chain.get("path_analysis", {}).get("path_length", 2) > 6
                    ]
                )
            else:
                avg_path_length = 0
                high_confidence_paths = 0
                complex_paths = 0

            summary["call_chains"] = {
                "total_paths": total_paths,
                "average_path_length": avg_path_length,
                "high_confidence_paths": high_confidence_paths,
                "complex_paths": complex_paths,
                "tracked_variables": len(self.all_tainted_vars),
                "tracked_functions": len(self.all_functions),
                "data_flow_edges": total_paths,  # Each call chain represents a data flow edge
            }
        elif self.visitor and hasattr(self.visitor, "call_chain_tracker"):
            # Fallback to tracker summary if available
            call_chain_summary = self.visitor.call_chain_tracker.get_summary()
            summary["call_chains"] = call_chain_summary
        else:
            # Provide default call chain summary if tracker is not available
            summary["call_chains"] = {
                "total_paths": 0,
                "average_path_length": 0,
                "high_confidence_paths": 0,
                "complex_paths": 0,
                "tracked_variables": 0,
                "tracked_functions": 0,
                "data_flow_edges": 0,
            }

        return summary

    def _update_global_state(
        self, visitor: TaintAnalysisVisitor, file_path: str
    ) -> None:
        """Update global analysis state with visitor results."""
        # Update global functions
        for func_name, func_info in visitor.functions.items():
            qualified_name = f"{file_path}::{func_name}"
            self.all_functions[qualified_name] = func_info

        # Update global tainted variables
        for var_name, taint_info in visitor.tainted.items():
            qualified_name = f"{file_path}::{var_name}"
            self.all_tainted_vars[qualified_name] = taint_info

        # Update module mapping
        self.module_map[os.path.basename(file_path).replace(".py", "")] = file_path

        # Collect import information
        import_info = visitor.import_tracker.get_import_summary()
        self.all_imports[file_path] = import_info

    def _convert_vulnerabilities(
        self, visitor: TaintAnalysisVisitor
    ) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Convert visitor vulnerabilities to standard format and extract call chains."""
        vulnerabilities = []
        call_chains = []

        # Track unique call chains to prevent duplicates
        seen_call_chains = set()

        for vuln in visitor.found_vulnerabilities:
            source_info = vuln.get("source", {})
            sink_info = vuln.get("sink", {})
            detection_type = vuln.get("detection_type", "traditional")

            # Handle sink-only detection differently
            if detection_type == "sink_only":
                vulnerability = {
                    "type": sink_info.get(
                        "vulnerability_type", "PotentialVulnerability"
                    ),
                    "severity": "Medium",  # Lower severity for sink-only detection
                    "detection_method": "sink_detection",
                    "sink": {
                        "name": sink_info.get("name", "Unknown"),
                        "line": sink_info.get("line", 0),
                        "file": visitor.file_path,
                        "function_name": sink_info.get("function_name", ""),
                        "full_name": sink_info.get("full_name", ""),
                    },
                    "argument": vuln.get("tainted_var", "unknown"),
                    "argument_index": vuln.get("arg_index", -1),
                    "description": f"Detected dangerous sink: {sink_info.get('name', 'Unknown')} at line {sink_info.get('line', 0)}",
                    "recommendation": "Review the arguments passed to this function to ensure they are properly validated and sanitized.",
                }
                vulnerabilities.append(vulnerability)
            else:
                # Traditional source-to-sink detection - don't add to vulnerabilities
                # since we now have dedicated call_chains for this information

                # Create a unique identifier for this call chain to prevent duplicates
                call_chain_key = (
                    source_info.get("name", "Unknown"),
                    source_info.get("line", 0),
                    sink_info.get("name", "Unknown"),
                    sink_info.get("line", 0),
                    vuln.get("tainted_var", ""),
                )

                # Skip if we've already seen this exact call chain
                if call_chain_key in seen_call_chains:
                    if self.debug:
                        log_debug(f"Skipping duplicate call chain: {call_chain_key}")
                    continue

                seen_call_chains.add(call_chain_key)

                # Extract call chain information separately
                call_chain_entry = {
                    "id": len(call_chains) + 1,  # Unique identifier
                    "source": {
                        "type": source_info.get("name", "Unknown"),
                        "line": source_info.get("line", 0),
                        "file": visitor.file_path,
                        "function": source_info.get("function_name", ""),
                    },
                    "sink": {
                        "type": sink_info.get("name", "Unknown"),
                        "line": sink_info.get("line", 0),
                        "file": visitor.file_path,
                        "function": sink_info.get("function_name", ""),
                        "full_name": sink_info.get("full_name", ""),
                    },
                    "tainted_variable": vuln.get("tainted_var", ""),
                    "vulnerability_type": sink_info.get(
                        "vulnerability_type", "Unknown"
                    ),
                    "flow_description": f"{source_info.get('name', 'source')} -> {sink_info.get('name', 'sink')}",
                }

                # Add detailed call chain information if available
                if "taint_path" in vuln:
                    taint_path = vuln["taint_path"]
                    call_chain_entry.update(
                        {
                            "path_analysis": {
                                "path_length": taint_path.path_length,
                                "confidence": taint_path.confidence,
                                "intermediate_steps": len(
                                    taint_path.intermediate_nodes
                                ),
                                "complexity": "low"
                                if taint_path.path_length <= 3
                                else "medium"
                                if taint_path.path_length <= 6
                                else "high",
                            },
                            "intermediate_nodes": [
                                {
                                    "function": node.function_name,
                                    "line": node.line_number,
                                    "type": node.node_type,
                                    "variable": node.variable_name,
                                }
                                for node in taint_path.intermediate_nodes
                            ],
                        }
                    )
                else:
                    # Default path analysis for simple flows
                    call_chain_entry["path_analysis"] = {
                        "path_length": 2,
                        "confidence": 1.0,
                        "intermediate_steps": 0,
                        "complexity": "low",
                    }
                    call_chain_entry["intermediate_nodes"] = []

                call_chains.append(call_chain_entry)

        return vulnerabilities, call_chains

    def _propagate_taint_across_functions(self) -> None:
        """Propagate taint information across function boundaries."""
        # This is a simplified version of cross-function taint propagation
        # In a full implementation, this would analyze call graphs and
        # propagate taint through function parameters and return values

        if self.debug:
            log_debug(
                "Cross-function taint propagation not yet implemented in refactored version"
            )

        # TODO: Implement cross-function taint propagation
        # This would involve:
        # 1. Building a complete call graph
        # 2. Analyzing function parameters and return values
        # 3. Propagating taint through function calls
        # 4. Detecting vulnerabilities across function boundaries
