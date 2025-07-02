"""
Enhanced taint tracker - refactored version.

This module provides the main orchestrator for taint analysis,
consolidating functionality from the original tracker while
simplifying the architecture.
"""

import ast
import gc
import os
import resource
import sys
from typing import Any, Dict, List, Optional, Set, Tuple, Type, TypeVar

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

        # Path-sensitive analysis configuration
        self.path_sensitive_enabled: bool = config.get(
            "path_sensitive_analysis", {}
        ).get("enabled", False)

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

        # Cross-file function mapping: function_name -> file_path
        self.cross_file_function_map: Dict[str, str] = {}
        # Import mapping: (file_path, imported_name) -> (source_file, function_name)
        self.import_function_map: Dict[Tuple[str, str], Tuple[str, str]] = {}

        # Core components
        self.ast_processor = ASTProcessor(debug)

        # Store last visitor for inspection
        self.visitor: Optional[TaintAnalysisVisitor] = None

        # Performance optimization: cache parsed ASTs
        self._ast_cache: Dict[
            str, Tuple[ast.AST, List[str], Dict[ast.AST, ast.AST]]
        ] = {}

        # Memory management
        self._memory_limit_mb = 1024  # Default 1GB limit
        self._cache_size_limit = 100  # Maximum number of cached ASTs

        # Memory management
        self._memory_limit_mb = 1024  # Default 1GB limit
        self._cache_size_limit = 100  # Maximum number of cached ASTs

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

        self.analyzed_files.add(file_path)

        if self.debug:
            log_debug(f"Analyzing file: {file_path}")

        # Check memory usage before processing
        self._check_memory_usage()

        try:
            # Use cached AST if available, otherwise parse the file
            if file_path in self._ast_cache:
                tree, source_lines, parent_map = self._ast_cache[file_path]
                if self.debug:
                    log_debug(f"Using cached AST for {file_path}")
            else:
                tree, source_lines, parent_map = self.ast_processor.parse_file(
                    file_path
                )
                if tree is not None:
                    self._ast_cache[file_path] = (tree, source_lines, parent_map)
                    if self.debug:
                        log_debug(f"Cached AST for {file_path}")

            if tree is None:
                return [], []

            # Store current file contents for context display
            if source_lines:
                self.current_file_contents = "".join(source_lines)

            # Create and configure visitor (always create fresh visitor for accurate analysis)
            visitor = TaintAnalysisVisitor(
                parent_map=parent_map,
                debug_mode=self.debug,
                verbose=False,
                file_path=file_path,
                source_lines=source_lines,
            )

            # Configure visitor with sources and sinks
            visitor.classifier.configure(self.sources, self.sinks, self.config)

            # Enable path-sensitive analysis if configured
            if self.path_sensitive_enabled:
                visitor.enable_path_sensitive_analysis(True)
                if self.debug:
                    log_debug(f"Enabled path-sensitive analysis for {file_path}")

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

    def analyze_multiple_files(
        self, file_paths: List[str]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Analyze multiple Python files with cross-file taint propagation.

        Args:
            file_paths: List of file paths to analyze

        Returns:
            Tuple of (vulnerabilities, call_chains) from all files
        """
        all_vulnerabilities = []
        all_call_chains = []
        processed_vulnerabilities_set = set()
        processed_call_chains_set = set()

        # First pass: analyze each file individually
        for file_path in file_paths:
            if self.debug:
                log_debug(f"Initial analysis pass for: {file_path}")

            vulnerabilities, call_chains = self.analyze_file(file_path)

            # Deduplicate vulnerabilities
            for vuln in vulnerabilities:
                # Create a hashable representation for deduplication
                vuln_key = self._create_vulnerability_key(vuln)
                if vuln_key not in processed_vulnerabilities_set:
                    all_vulnerabilities.append(vuln)
                    processed_vulnerabilities_set.add(vuln_key)

            # Deduplicate call chains
            for call_chain in call_chains:
                # Create a hashable representation for call chain deduplication
                chain_key = self._create_call_chain_key(call_chain)
                if chain_key not in processed_call_chains_set:
                    all_call_chains.append(call_chain)
                    processed_call_chains_set.add(chain_key)

        # Second pass: propagate taint across function calls
        if self.debug:
            log_debug("Propagating taint information across all analyzed functions...")

        cross_function_vulnerabilities = self._propagate_taint_across_functions()

        # Third pass: collect cross-function vulnerabilities
        for vuln in cross_function_vulnerabilities:
            vuln_key = self._create_vulnerability_key(vuln)
            if vuln_key not in processed_vulnerabilities_set:
                all_vulnerabilities.append(vuln)
                processed_vulnerabilities_set.add(vuln_key)

        # Fourth pass: collect any new vulnerabilities found through visitor updates
        for file_path in file_paths:
            if self.visitor and hasattr(self.visitor, "found_vulnerabilities"):
                # Check for any new vulnerabilities that might have been discovered
                new_vulnerabilities, _ = self._convert_vulnerabilities(self.visitor)
                for vuln in new_vulnerabilities:
                    vuln_key = self._create_vulnerability_key(vuln)
                    if vuln_key not in processed_vulnerabilities_set:
                        all_vulnerabilities.append(vuln)
                        processed_vulnerabilities_set.add(vuln_key)

        if self.debug:
            log_debug(
                f"Multi-file analysis completed: {len(all_vulnerabilities)} vulnerabilities, {len(all_call_chains)} call chains"
            )

        return all_vulnerabilities, all_call_chains

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

            for _, import_info in self.all_imports.items():
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

            # Build cross-file function mapping
            self.cross_file_function_map[func_name] = file_path

        # Update global tainted variables
        for var_name, taint_info in visitor.tainted.items():
            qualified_name = f"{file_path}::{var_name}"
            self.all_tainted_vars[qualified_name] = taint_info

        # Update module mapping
        self.module_map[os.path.basename(file_path).replace(".py", "")] = file_path

        # Collect import information
        import_info = visitor.import_tracker.get_import_summary()
        self.all_imports[file_path] = import_info

        # Build import-to-function mapping for cross-file call resolution
        self._build_import_function_mapping(visitor, file_path)

    def _build_import_function_mapping(
        self, visitor: TaintAnalysisVisitor, file_path: str
    ) -> None:
        """Build mapping from imported functions to their source files."""
        if not hasattr(visitor, "import_tracker"):
            return

        import_tracker = visitor.import_tracker

        # Process from imports (from module import function)
        for imported_name, full_name in import_tracker.from_imports.items():
            if "." in full_name:
                module_name, func_name = full_name.rsplit(".", 1)

                # Try to find the source file for this module
                source_file = self._resolve_module_to_file(module_name)
                if source_file:
                    # Map (current_file, imported_name) -> (source_file, function_name)
                    self.import_function_map[(file_path, imported_name)] = (
                        source_file,
                        func_name,
                    )

                    if self.debug:
                        log_debug(
                            f"Mapped import {imported_name} in {file_path} to {func_name} in {source_file}"
                        )

        # Process direct imports (import module)
        for alias, module_name in import_tracker.import_aliases.items():
            source_file = self._resolve_module_to_file(module_name)
            if source_file:
                # For direct imports, we'll resolve function calls at call time
                if self.debug:
                    log_debug(
                        f"Mapped module alias {alias} in {file_path} to {source_file}"
                    )

    def _resolve_module_to_file(self, module_name: str) -> Optional[str]:
        """Resolve a module name to its file path."""
        # Simple resolution: check if we have a file with matching name
        module_basename = module_name.split(".")[-1]

        # Check in module_map first
        if module_basename in self.module_map:
            return self.module_map[module_basename]

        # Check in analyzed files
        for file_path in self.analyzed_files:
            file_basename = os.path.basename(file_path).replace(".py", "")
            if file_basename == module_basename:
                return file_path

        return None

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
                    # Path-sensitive analysis information
                    "path_reachable": vuln.get("path_reachable", True),
                    "path_constraints": vuln.get("path_constraints", "No constraints"),
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
                    # Path-sensitive analysis information
                    "path_reachable": vuln.get("path_reachable", True),
                    "path_constraints": vuln.get("path_constraints", "No constraints"),
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

    def _create_vulnerability_key(self, vuln: Dict[str, Any]) -> str:
        """Create a hashable key for vulnerability deduplication."""
        # Create a simple string key based on key vulnerability attributes
        vuln_type = vuln.get("type", "Unknown")
        detection_method = vuln.get("detection_method", "Unknown")

        # Handle sink information
        sink_info = vuln.get("sink", {})
        sink_name = sink_info.get("name", "Unknown")
        sink_line = sink_info.get("line", 0)
        sink_file = sink_info.get("file", "Unknown")

        # Handle source information (may not exist for sink-only detection)
        source_info = vuln.get("source", {})
        source_type = source_info.get("type", "Unknown")
        source_line = source_info.get("line", 0)

        # Create a unique key
        key = f"{vuln_type}:{detection_method}:{sink_name}:{sink_line}:{sink_file}:{source_type}:{source_line}"
        return key

    def _create_call_chain_key(self, call_chain: Dict[str, Any]) -> str:
        """Create a hashable key for call chain deduplication."""
        # Create a simple string key based on key call chain attributes
        chain_type = call_chain.get("type", "Unknown")
        source_func = call_chain.get("source_function", "Unknown")
        target_func = call_chain.get("target_function", "Unknown")

        # Handle source information
        source_info = call_chain.get("source", {})
        source_line = source_info.get("line", 0)
        source_file = source_info.get("file", "Unknown")

        # Handle target information
        target_info = call_chain.get("target", {})
        target_line = target_info.get("line", 0)
        target_file = target_info.get("file", "Unknown")

        # Create a unique key
        key = f"{chain_type}:{source_func}:{target_func}:{source_line}:{source_file}:{target_line}:{target_file}"
        return key

    def reset_analysis_state(self) -> None:
        """Reset the analysis state to allow re-analysis of files."""
        self.analyzed_files.clear()
        self.all_functions.clear()
        self.all_tainted_vars.clear()
        self.all_imports.clear()
        self.visitor = None
        self.current_file_contents = None

        # Clear cross-file mappings
        self.cross_file_function_map.clear()
        self.import_function_map.clear()

        # Clear performance cache
        self._ast_cache.clear()

        if self.debug:
            log_debug("Analysis state, cross-file mappings, and AST cache reset")

    def _check_memory_usage(self) -> None:
        """Check memory usage and clean up if necessary."""
        try:
            # Get current memory usage in MB
            memory_usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            # On macOS, ru_maxrss is in bytes; on Linux, it's in KB
            if sys.platform == "darwin":
                memory_mb = memory_usage / (1024 * 1024)
            else:
                memory_mb = memory_usage / 1024

            if self.debug:
                log_debug(f"Current memory usage: {memory_mb:.2f} MB")

            # Check if we're approaching memory limit
            if memory_mb > self._memory_limit_mb * 0.8:  # 80% threshold
                if self.debug:
                    log_debug(f"Memory usage high ({memory_mb:.2f} MB), cleaning up...")
                self._cleanup_memory()

            # Check cache size
            if len(self._ast_cache) > self._cache_size_limit:
                if self.debug:
                    log_debug(
                        f"AST cache size ({len(self._ast_cache)}) exceeds limit, cleaning up..."
                    )
                self._cleanup_ast_cache()

        except Exception as e:
            if self.debug:
                log_debug(f"Error checking memory usage: {e}")

    def _cleanup_memory(self) -> None:
        """Clean up memory by removing old cached data."""
        # Clear AST cache
        self._ast_cache.clear()

        # Force garbage collection
        gc.collect()

        if self.debug:
            log_debug("Memory cleanup completed")

    def _cleanup_ast_cache(self) -> None:
        """Clean up AST cache by removing oldest entries."""
        # Keep only the most recent entries (simple FIFO)
        cache_items = list(self._ast_cache.items())
        keep_count = self._cache_size_limit // 2  # Keep half

        # Clear cache and keep only recent entries
        self._ast_cache.clear()
        for key, value in cache_items[-keep_count:]:
            self._ast_cache[key] = value

        if self.debug:
            log_debug(f"AST cache cleaned up, kept {len(self._ast_cache)} entries")

    def _propagate_taint_across_functions(self) -> List[Dict[str, Any]]:
        """Propagate taint information across function boundaries and return new vulnerabilities."""
        if self.debug:
            log_debug("Starting cross-function taint propagation...")

        # Step 1: Build complete call graph
        call_graph = self._build_call_graph()

        # Step 2: Analyze function parameters and return values
        self._analyze_function_signatures()

        # Step 3: Initialize taint state from existing analysis
        self._initialize_taint_state(call_graph)

        # Step 4: Propagate taint through function calls
        self._propagate_taint_through_calls(call_graph)

        # Step 5: Detect new vulnerabilities across function boundaries
        new_vulnerabilities = self._detect_cross_function_vulnerabilities(call_graph)

        if self.debug:
            log_debug(
                f"Cross-function analysis found {len(new_vulnerabilities)} additional vulnerabilities"
            )

        return new_vulnerabilities

    def _build_call_graph(self) -> Dict[str, Dict[str, Any]]:
        """Build a complete call graph from all analyzed functions."""
        call_graph = {}

        if self.debug:
            log_debug("Building call graph from analyzed functions...")

        # Initialize nodes for all functions (optimized with dict comprehension)
        call_graph = {
            qualified_name: {
                "info": func_info,
                "callers": [],
                "callees": [],
                "tainted_params": set(),
                "returns_tainted": False,
                "taint_sources": [],
            }
            for qualified_name, func_info in self.all_functions.items()
        }

        # Build call relationships by analyzing function calls in each file
        # Use batch processing to reduce overhead
        for file_path in self.analyzed_files:
            self._analyze_calls_in_file(file_path, call_graph)

        if self.debug:
            log_debug(f"Built call graph with {len(call_graph)} nodes")

        return call_graph

    def _analyze_calls_in_file(
        self, file_path: str, call_graph: Dict[str, Dict[str, Any]]
    ) -> None:
        """Analyze function calls within a specific file to build call relationships."""
        try:
            # Use cached AST if available, otherwise parse the file
            if file_path in self._ast_cache:
                tree, _, _ = self._ast_cache[file_path]
                if self.debug:
                    log_debug(f"Using cached AST for call analysis in {file_path}")
            else:
                tree, source_lines, parent_map = self.ast_processor.parse_file(
                    file_path
                )
                if tree is not None:
                    self._ast_cache[file_path] = (tree, source_lines, parent_map)
                    if self.debug:
                        log_debug(f"Cached AST during call analysis for {file_path}")

            if tree is None:
                return

            # Create a call analyzer visitor with cross-file support
            call_analyzer = CallGraphAnalyzer(
                file_path,
                call_graph,
                self.all_functions,
                self.debug,
                self.import_function_map,
                self.cross_file_function_map,
            )
            call_analyzer.visit(tree)

        except Exception as e:
            if self.debug:
                log_debug(f"Error analyzing calls in {file_path}: {e}")

    def _analyze_function_signatures(self) -> None:
        """Analyze function signatures to understand parameter flow."""
        if self.debug:
            log_debug("Analyzing function signatures for parameter flow...")

        for _, func_info in self.all_functions.items():
            # Extract parameter information
            args = func_info.get("args", [])
            node = func_info.get("node")

            if node and hasattr(node, "args"):
                # Store parameter names and positions
                func_info["param_positions"] = {arg: i for i, arg in enumerate(args)}
                func_info["param_count"] = len(args)

                # Check for default values that might be tainted
                if hasattr(node.args, "defaults") and node.args.defaults:
                    func_info["has_defaults"] = True
                else:
                    func_info["has_defaults"] = False

    def _initialize_taint_state(self, call_graph: Dict[str, Dict[str, Any]]) -> None:
        """Initialize taint state for functions based on existing taint analysis."""
        if self.debug:
            log_debug("Initializing taint state for cross-function analysis...")

        # For each function, check if any of its parameters correspond to tainted variables
        for func_qualified_name, func_data in call_graph.items():
            func_info = func_data["info"]
            args = func_info.get("args", [])

            if self.debug:
                log_debug(f"Checking taint state for function: {func_qualified_name}")

            # Check if this function has parameters that match tainted variables
            for param_index, param_name in enumerate(args):
                param_already_tainted = False

                # Check if this parameter is tainted in the function's context
                param_qualified_name = f"{func_qualified_name}::{param_name}"

                # Also check for the parameter in the global tainted variables
                if param_qualified_name in self.all_tainted_vars:
                    func_data["tainted_params"].add(param_index)
                    param_already_tainted = True
                    if self.debug:
                        log_debug(
                            f"  Parameter {param_name} (index {param_index}) is directly tainted"
                        )

                # If not already tainted, check if the parameter name matches any tainted variable pattern
                if not param_already_tainted:
                    # Get the file path for this function
                    file_path = (
                        func_qualified_name.split("::")[0]
                        if "::" in func_qualified_name
                        else ""
                    )

                    # Look for tainted variables in the same file that match this parameter
                    for tainted_var_name, taint_info in self.all_tainted_vars.items():
                        # Only consider tainted variables from the same file
                        if not tainted_var_name.startswith(file_path):
                            continue

                        # Extract the variable name from qualified name
                        var_name = (
                            tainted_var_name.split("::")[-1]
                            if "::" in tainted_var_name
                            else tainted_var_name
                        )

                        # If parameter name matches a tainted variable, mark it as tainted
                        if param_name == var_name:
                            func_data["tainted_params"].add(param_index)

                            # Record taint source (avoid duplicates)
                            taint_source = {
                                "from_variable": tainted_var_name,
                                "parameter_index": param_index,
                                "taint_type": taint_info.get("name", "Unknown"),
                            }

                            # Check if this source is already recorded
                            if taint_source not in func_data["taint_sources"]:
                                func_data["taint_sources"].append(taint_source)

                            param_already_tainted = True

                            if self.debug:
                                log_debug(
                                    f"  Parameter {param_name} (index {param_index}) matches tainted variable {var_name}"
                                )
                            break  # Only match the first tainted variable with this name

            # Check if this function returns tainted data based on its implementation
            # This is a heuristic - if the function calls any sinks, it might return tainted data
            if self._function_potentially_returns_tainted_data(
                func_qualified_name, func_info
            ):
                func_data["returns_tainted"] = True
                if self.debug:
                    log_debug(
                        f"  Function {func_qualified_name} potentially returns tainted data"
                    )

        if self.debug:
            tainted_functions = sum(
                1 for f in call_graph.values() if f["tainted_params"]
            )
            log_debug(
                f"Initialized taint state: {tainted_functions} functions have tainted parameters"
            )

    def _function_potentially_returns_tainted_data(
        self, func_qualified_name: str, func_info: Dict[str, Any]
    ) -> bool:
        """Check if a function potentially returns tainted data."""
        # Suppress unused variable warnings
        _ = func_qualified_name
        _ = func_info

        # This is a simple heuristic - in a more sophisticated implementation,
        # this would analyze the function's AST to determine if it returns tainted data

        # For now, we'll assume that functions that take tainted parameters
        # and don't call sinks might return tainted data
        return False  # Conservative approach for now

    def _propagate_taint_through_calls(
        self, call_graph: Dict[str, Dict[str, Any]]
    ) -> None:
        """Propagate taint through function calls using the call graph."""
        if self.debug:
            log_debug("Propagating taint through function calls...")

        # Optimized iterative propagation with early termination
        max_iterations = 10  # Prevent infinite loops
        iteration = 0
        taint_changed = True

        # Track functions that have been processed to avoid redundant work
        processed_functions = set()

        while taint_changed and iteration < max_iterations:
            taint_changed = False
            iteration += 1
            current_processed = set()

            if self.debug:
                log_debug(f"Taint propagation iteration {iteration}")

            # Only process functions that might have new taint information
            functions_to_process = (
                call_graph.keys()
                if iteration == 1
                else [f for f in call_graph.keys() if f not in processed_functions]
            )

            for func_name in functions_to_process:
                func_data = call_graph[func_name]
                func_changed = False

                # Check if this function has tainted parameters
                if self._has_tainted_parameters(func_name, func_data):
                    # Propagate taint to callees
                    for callee_info in func_data["callees"]:
                        if self._propagate_to_callee(
                            func_name, callee_info, call_graph
                        ):
                            taint_changed = True
                            func_changed = True

                # Check if this function returns tainted data
                if func_data["returns_tainted"]:
                    # Propagate taint to callers
                    for caller_info in func_data["callers"]:
                        if self._propagate_to_caller(
                            func_name, caller_info, call_graph
                        ):
                            taint_changed = True
                            func_changed = True

                # Mark function as processed if no changes occurred
                if not func_changed:
                    current_processed.add(func_name)

            # Update processed functions set
            processed_functions.update(current_processed)

        if self.debug:
            log_debug(f"Taint propagation completed after {iteration} iterations")

    def _has_tainted_parameters(
        self, func_name: str, func_data: Dict[str, Any]
    ) -> bool:
        """Check if a function has any tainted parameters."""
        _ = func_name  # Suppress unused variable warning
        return len(func_data["tainted_params"]) > 0

    def _propagate_to_callee(
        self,
        caller_name: str,
        callee_info: Dict[str, Any],
        call_graph: Dict[str, Dict[str, Any]],
    ) -> bool:
        """Propagate taint from caller to callee through parameters."""
        callee_name = callee_info["name"]
        call_args = callee_info.get("args", [])

        if callee_name not in call_graph:
            return False

        callee_data = call_graph[callee_name]
        original_tainted_params = callee_data["tainted_params"].copy()

        # Check each argument for taint
        for arg_index, arg_info in enumerate(call_args):
            if self._is_argument_tainted(arg_info, caller_name):
                callee_data["tainted_params"].add(arg_index)

                # Track taint source
                taint_source = {
                    "from_function": caller_name,
                    "parameter_index": arg_index,
                    "call_line": callee_info.get("line", 0),
                }
                callee_data["taint_sources"].append(taint_source)

        # Return True if new taint was added
        return len(callee_data["tainted_params"]) > len(original_tainted_params)

    def _propagate_to_caller(
        self,
        callee_name: str,
        caller_info: Dict[str, Any],
        call_graph: Dict[str, Dict[str, Any]],
    ) -> bool:
        """Propagate taint from callee return value to caller."""
        caller_name = caller_info["name"]

        if caller_name not in call_graph:
            return False

        _ = call_graph[caller_name]  # Suppress unused variable warning

        # Mark the call site as potentially returning tainted data
        call_line = caller_info.get("line", 0)
        assignment_var = caller_info.get("assignment_var")

        if assignment_var:
            # Mark the assignment variable as tainted in the caller's context
            qualified_var_name = f"{caller_name}::{assignment_var}"
            if qualified_var_name not in self.all_tainted_vars:
                self.all_tainted_vars[qualified_var_name] = {
                    "name": "cross_function_return",
                    "line": call_line,
                    "from_function": callee_name,
                }
                return True

        return False

    def _is_argument_tainted(self, arg_info: Dict[str, Any], caller_name: str) -> bool:
        """Check if a function call argument is tainted."""
        arg_name = arg_info.get("name", "")

        # Check if the argument variable is tainted in the caller's context
        qualified_var_name = f"{caller_name}::{arg_name}"
        if qualified_var_name in self.all_tainted_vars:
            return True

        # Check for direct taint in the argument expression
        if arg_info.get("is_tainted", False):
            return True

        return False

    def _detect_cross_function_vulnerabilities(
        self, call_graph: Dict[str, Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Detect vulnerabilities that span across function boundaries."""
        vulnerabilities = []

        if self.debug:
            log_debug("Detecting cross-function vulnerabilities...")

        for func_name, func_data in call_graph.items():
            # Check if this function has tainted parameters and calls sinks
            if func_data["tainted_params"]:
                sink_calls = self._find_sink_calls_in_function(func_name, func_data)

                for sink_call in sink_calls:
                    # Check if tainted parameters flow to sink arguments
                    if self._tainted_params_flow_to_sink(
                        func_data["tainted_params"], sink_call
                    ):
                        vulnerability = self._create_cross_function_vulnerability(
                            func_name, func_data, sink_call
                        )
                        vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _find_sink_calls_in_function(
        self, func_name: str, func_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Find sink function calls within a specific function."""
        sink_calls = []

        # Extract file path from qualified function name
        if "::" in func_name:
            file_path = func_name.split("::")[0]
        else:
            return sink_calls

        try:
            # Re-parse the function to find sink calls
            tree, _, _ = self.ast_processor.parse_file(file_path)
            if tree is None:
                return sink_calls

            # Find the specific function node
            func_node = func_data["info"].get("node")
            if func_node is None:
                return sink_calls

            # Create an enhanced sink finder that can detect external module calls
            sink_finder = EnhancedSinkFinder(self.sinks, self.debug)
            sink_finder.visit(func_node)
            sink_calls = sink_finder.found_sinks

            if self.debug and sink_calls:
                log_debug(f"Found {len(sink_calls)} sink calls in function {func_name}")
                for sink in sink_calls:
                    log_debug(
                        f"  - {sink.get('name', 'Unknown')} at line {sink.get('line', 0)}"
                    )

        except Exception as e:
            if self.debug:
                log_debug(f"Error finding sinks in function {func_name}: {e}")

        return sink_calls

    def _tainted_params_flow_to_sink(
        self, tainted_params: set, sink_call: Dict[str, Any]
    ) -> bool:
        """Check if tainted parameters flow to sink arguments."""
        # This is a simplified check - in a full implementation, this would
        # perform more sophisticated data flow analysis
        sink_args = sink_call.get("args", [])

        for _, arg in enumerate(sink_args):
            # Check if this argument uses any tainted parameters
            if self._argument_uses_tainted_params(arg, tainted_params):
                return True

        return False

    def _argument_uses_tainted_params(
        self, arg: Dict[str, Any], tainted_params: set
    ) -> bool:
        """Check if a sink argument uses any tainted parameters."""
        # Simple heuristic: check if argument name matches any parameter
        _ = arg.get("name", "")  # Suppress unused variable warning

        # If the argument index is in tainted_params, it's tainted
        arg_index = arg.get("index", -1)
        if arg_index in tainted_params:
            return True

        # Additional checks could be added here for more complex expressions
        return False

    def _create_cross_function_vulnerability(
        self, func_name: str, func_data: Dict[str, Any], sink_call: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a vulnerability record for cross-function taint flow."""
        # Find the original taint source
        taint_sources = func_data.get("taint_sources", [])
        source_info = taint_sources[0] if taint_sources else {}

        vulnerability = {
            "type": sink_call.get("vulnerability_type", "CrossFunctionTaint"),
            "severity": "High",  # Cross-function vulnerabilities are typically more serious
            "detection_method": "cross_function_analysis",
            "source": {
                "function": source_info.get("from_function", "Unknown"),
                "parameter_index": source_info.get("parameter_index", -1),
                "line": source_info.get("call_line", 0),
            },
            "sink": {
                "name": sink_call.get("name", "Unknown"),
                "function": func_name,
                "line": sink_call.get("line", 0),
                "file": func_name.split("::")[0] if "::" in func_name else "Unknown",
            },
            "flow_path": f"Cross-function: {source_info.get('from_function', 'Unknown')} -> {func_name}",
            "description": f"Tainted data flows from {source_info.get('from_function', 'Unknown')} to sink {sink_call.get('name', 'Unknown')} in {func_name}",
            "recommendation": "Review the data flow between these functions and ensure proper validation is performed.",
        }

        return vulnerability


class CallGraphAnalyzer(ast.NodeVisitor):
    """AST visitor for analyzing function calls to build call graph."""

    def __init__(
        self,
        file_path: str,
        call_graph: Dict[str, Dict[str, Any]],
        all_functions: Dict[str, Any],
        debug: bool = False,
        import_function_map: Dict[Tuple[str, str], Tuple[str, str]] = None,
        cross_file_function_map: Dict[str, str] = None,
    ):
        self.file_path = file_path
        self.call_graph = call_graph
        self.all_functions = all_functions
        self.debug = debug
        self.current_function = None

        # Cross-file analysis support
        self.import_function_map = import_function_map or {}
        self.cross_file_function_map = cross_file_function_map or {}

        # Enhanced function call tracking
        self.recursive_calls = set()  # Track recursive function calls
        self.method_calls = []  # Track object method calls
        self.dynamic_calls = []  # Track dynamic function calls

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definition to set current function context."""
        qualified_name = f"{self.file_path}::{node.name}"
        self.current_function = qualified_name
        self.generic_visit(node)
        self.current_function = None

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit async function definition to set current function context."""
        qualified_name = f"{self.file_path}::{node.name}"
        self.current_function = qualified_name
        self.generic_visit(node)
        self.current_function = None

    def visit_Call(self, node: ast.Call) -> None:
        """Visit function calls to build call relationships."""
        if self.current_function is None:
            self.generic_visit(node)
            return

        # Extract function name from call
        func_name = self._extract_function_name(node)
        if not func_name:
            self.generic_visit(node)
            return

        # Find the callee in our function registry
        callee_qualified_name = self._find_callee_qualified_name(func_name)

        if callee_qualified_name and callee_qualified_name in self.call_graph:
            # Check for recursive call
            if callee_qualified_name == self.current_function:
                self.recursive_calls.add(self.current_function)
                if self.debug:
                    log_debug(f"Detected recursive call in {self.current_function}")

            # Add call relationship
            caller_data = self.call_graph[self.current_function]
            callee_data = self.call_graph[callee_qualified_name]

            # Add callee to caller's callees list
            callee_info = {
                "name": callee_qualified_name,
                "line": getattr(node, "lineno", 0),
                "args": self._extract_call_arguments(node),
                "is_recursive": callee_qualified_name == self.current_function,
                "call_type": self._determine_call_type(node),
            }

            if callee_info not in caller_data["callees"]:
                caller_data["callees"].append(callee_info)

            # Add caller to callee's callers list
            caller_info = {
                "name": self.current_function,
                "line": getattr(node, "lineno", 0),
                "is_recursive": callee_qualified_name == self.current_function,
            }

            if caller_info not in callee_data["callers"]:
                callee_data["callers"].append(caller_info)

            if self.debug:
                call_type = (
                    "recursive"
                    if callee_qualified_name == self.current_function
                    else "normal"
                )
                log_debug(
                    f"Added {call_type} call relationship: {self.current_function} -> {callee_qualified_name}"
                )

        self.generic_visit(node)

    def _extract_function_name(self, node: ast.Call) -> Optional[str]:
        """Extract function name from call node, supporting various call types."""
        if isinstance(node.func, ast.Name):
            # Simple function call: func()
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            # Method call: obj.method() or module.func()
            method_name = node.func.attr

            # Track as method call for enhanced analysis
            if isinstance(node.func.value, ast.Name):
                obj_name = node.func.value.id
                self.method_calls.append(
                    {
                        "object": obj_name,
                        "method": method_name,
                        "line": getattr(node, "lineno", 0),
                        "node": node,
                    }
                )

                if self.debug:
                    log_debug(f"Tracked method call: {obj_name}.{method_name}")

            return method_name
        elif isinstance(node.func, ast.Subscript):
            # Dynamic function call: funcs[key]() or globals()['func']()
            self.dynamic_calls.append(
                {"type": "subscript", "line": getattr(node, "lineno", 0), "node": node}
            )

            if self.debug:
                log_debug(
                    f"Tracked dynamic subscript call at line {getattr(node, 'lineno', 0)}"
                )

            return "dynamic_subscript_call"
        elif isinstance(node.func, ast.Call):
            # Dynamic function call: getattr(obj, 'method')()
            if (
                isinstance(node.func.func, ast.Name)
                and node.func.func.id == "getattr"
                and len(node.func.args) >= 2
            ):
                # Extract method name from getattr
                if isinstance(node.func.args[1], ast.Constant):
                    method_name = node.func.args[1].value

                    self.dynamic_calls.append(
                        {
                            "type": "getattr",
                            "method": method_name,
                            "line": getattr(node, "lineno", 0),
                            "node": node,
                        }
                    )

                    if self.debug:
                        log_debug(f"Tracked dynamic getattr call: {method_name}")

                    return method_name

            # Other dynamic calls
            self.dynamic_calls.append(
                {
                    "type": "function_call",
                    "line": getattr(node, "lineno", 0),
                    "node": node,
                }
            )

            return "dynamic_function_call"

        return None

    def _determine_call_type(self, node: ast.Call) -> str:
        """Determine the type of function call."""
        if isinstance(node.func, ast.Name):
            return "function_call"
        elif isinstance(node.func, ast.Attribute):
            return "method_call"
        elif isinstance(node.func, ast.Subscript):
            return "dynamic_subscript_call"
        elif isinstance(node.func, ast.Call):
            if isinstance(node.func.func, ast.Name) and node.func.func.id == "getattr":
                return "dynamic_getattr_call"
            return "dynamic_function_call"
        else:
            return "unknown_call"

    def _find_callee_qualified_name(self, func_name: str) -> Optional[str]:
        """Find the qualified name of the callee function, including cross-file imports."""
        # First, try to find in the same file
        same_file_qualified = f"{self.file_path}::{func_name}"
        if same_file_qualified in self.all_functions:
            return same_file_qualified

        # Check if this is an imported function
        import_key = (self.file_path, func_name)
        if import_key in self.import_function_map:
            source_file, source_func_name = self.import_function_map[import_key]
            cross_file_qualified = f"{source_file}::{source_func_name}"
            if cross_file_qualified in self.all_functions:
                if self.debug:
                    log_debug(
                        f"Resolved cross-file call: {func_name} -> {cross_file_qualified}"
                    )
                return cross_file_qualified

        # Check if function exists in cross-file function map
        if func_name in self.cross_file_function_map:
            source_file = self.cross_file_function_map[func_name]
            cross_file_qualified = f"{source_file}::{func_name}"
            if cross_file_qualified in self.all_functions:
                if self.debug:
                    log_debug(
                        f"Resolved cross-file call via function map: {func_name} -> {cross_file_qualified}"
                    )
                return cross_file_qualified

        # Fallback: search in other files (less efficient but comprehensive)
        for qualified_name in self.all_functions.keys():
            if qualified_name.endswith(f"::{func_name}"):
                if self.debug:
                    log_debug(
                        f"Resolved cross-file call via search: {func_name} -> {qualified_name}"
                    )
                return qualified_name

        return None

    def _extract_call_arguments(self, node: ast.Call) -> List[Dict[str, Any]]:
        """Extract argument information from function call."""
        args = []
        for i, arg in enumerate(node.args):
            arg_info = {
                "index": i,
                "name": self._get_arg_name(arg),
                "type": type(arg).__name__,
            }
            args.append(arg_info)
        return args

    def _get_arg_name(self, arg: ast.expr) -> str:
        """Get the name of an argument expression."""
        if isinstance(arg, ast.Name):
            return arg.id
        elif isinstance(arg, ast.Constant):
            return str(arg.value)
        elif isinstance(arg, ast.Attribute):
            return f"{self._get_arg_name(arg.value)}.{arg.attr}"
        else:
            return f"<{type(arg).__name__}>"


class SinkFinder(ast.NodeVisitor):
    """AST visitor for finding sink function calls within a function."""

    def __init__(self, sinks: List[Dict[str, Any]], debug: bool = False):
        self.sinks = sinks
        self.debug = debug
        self.found_sinks = []

    def visit_Call(self, node: ast.Call) -> None:
        """Visit function calls to find sinks."""
        func_name = self._extract_function_name(node)
        if func_name and self._is_sink(func_name):
            sink_info = {
                "name": func_name,
                "line": getattr(node, "lineno", 0),
                "args": self._extract_call_arguments(node),
                "vulnerability_type": self._get_sink_vulnerability_type(func_name),
            }
            self.found_sinks.append(sink_info)

        self.generic_visit(node)

    def _extract_function_name(self, node: ast.Call) -> Optional[str]:
        """Extract function name from call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    def _is_sink(self, func_name: str) -> bool:
        """Check if function name is a sink."""
        for sink in self.sinks:
            if sink.get("name") == func_name or sink.get("pattern") == func_name:
                return True
        return False

    def _get_sink_vulnerability_type(self, func_name: str) -> str:
        """Get vulnerability type for a sink function."""
        for sink in self.sinks:
            if sink.get("name") == func_name or sink.get("pattern") == func_name:
                return sink.get("vulnerability_type", "Unknown")
        return "Unknown"

    def _extract_call_arguments(self, node: ast.Call) -> List[Dict[str, Any]]:
        """Extract argument information from function call."""
        args = []
        for i, arg in enumerate(node.args):
            arg_info = {
                "index": i,
                "name": self._get_arg_name(arg),
                "type": type(arg).__name__,
            }
            args.append(arg_info)
        return args

    def _get_arg_name(self, arg: ast.expr) -> str:
        """Get the name of an argument expression."""
        if isinstance(arg, ast.Name):
            return arg.id
        elif isinstance(arg, ast.Constant):
            return str(arg.value)
        elif isinstance(arg, ast.Attribute):
            return f"{self._get_arg_name(arg.value)}.{arg.attr}"
        else:
            return f"<{type(arg).__name__}>"


class EnhancedSinkFinder(ast.NodeVisitor):
    """Enhanced AST visitor for finding sink function calls, including external module calls."""

    def __init__(self, sinks: List[Dict[str, Any]], debug: bool = False):
        self.sinks = sinks
        self.debug = debug
        self.found_sinks = []

    def visit_Call(self, node: ast.Call) -> None:
        """Visit function calls to find sinks, including external module calls."""
        func_name = self._extract_function_name(node)
        full_name = self._extract_full_function_name(node)

        # Check both simple name and full name against sink patterns
        if (func_name and self._is_sink(func_name)) or (
            full_name and self._is_sink(full_name)
        ):
            sink_info = {
                "name": func_name or full_name,
                "full_name": full_name,
                "line": getattr(node, "lineno", 0),
                "args": self._extract_call_arguments(node),
                "vulnerability_type": self._get_sink_vulnerability_type(
                    func_name or full_name
                ),
            }
            self.found_sinks.append(sink_info)

            if self.debug:
                log_debug(
                    f"Found sink: {func_name or full_name} (full: {full_name}) at line {sink_info['line']}"
                )

        self.generic_visit(node)

    def _extract_function_name(self, node: ast.Call) -> Optional[str]:
        """Extract simple function name from call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    def _extract_full_function_name(self, node: ast.Call) -> Optional[str]:
        """Extract full function name including module path."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            # Handle module.function calls
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            elif isinstance(node.func.value, ast.Attribute):
                # Handle nested attributes like module.submodule.function
                parts = []
                current = node.func
                while isinstance(current, ast.Attribute):
                    parts.append(current.attr)
                    current = current.value
                if isinstance(current, ast.Name):
                    parts.append(current.id)
                    return ".".join(reversed(parts))
        return None

    def _is_sink(self, func_name: str) -> bool:
        """Check if function name matches any sink pattern."""
        for sink in self.sinks:
            patterns = sink.get("patterns", [])
            if isinstance(patterns, list):
                for pattern in patterns:
                    if pattern in func_name or func_name in pattern:
                        return True
            # Also check legacy format
            if sink.get("name") == func_name or sink.get("pattern") == func_name:
                return True
        return False

    def _get_sink_vulnerability_type(self, func_name: str) -> str:
        """Get vulnerability type for a sink function."""
        for sink in self.sinks:
            patterns = sink.get("patterns", [])
            if isinstance(patterns, list):
                for pattern in patterns:
                    if pattern in func_name or func_name in pattern:
                        return sink.get("vulnerability_type", "Unknown")
            # Also check legacy format
            if sink.get("name") == func_name or sink.get("pattern") == func_name:
                return sink.get("vulnerability_type", "Unknown")
        return "Unknown"

    def _extract_call_arguments(self, node: ast.Call) -> List[Dict[str, Any]]:
        """Extract argument information from function call."""
        args = []
        for i, arg in enumerate(node.args):
            arg_info = {
                "index": i,
                "name": self._get_arg_name(arg),
                "type": type(arg).__name__,
            }
            args.append(arg_info)
        return args

    def _get_arg_name(self, arg: ast.expr) -> str:
        """Get the name of an argument expression."""
        if isinstance(arg, ast.Name):
            return arg.id
        elif isinstance(arg, ast.Constant):
            return str(arg.value)
        elif isinstance(arg, ast.Attribute):
            return f"{self._get_arg_name(arg.value)}.{arg.attr}"
        else:
            return f"<{type(arg).__name__}>"
