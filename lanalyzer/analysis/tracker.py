"""
Enhanced taint tracker implementation.
"""

import ast
import os
import traceback
from typing import Any, Dict, List, Tuple, Set

from lanalyzer.analysis.ast_parser import ParentNodeVisitor
from lanalyzer.analysis.visitor import EnhancedTaintAnalysisVisitor
from lanalyzer.analysis.call_chain import CallChainBuilder
from lanalyzer.analysis.vulnerability_finder import VulnerabilityFinder
from lanalyzer.analysis.utils import TaintAnalysisUtils
from lanalyzer.logger import (
    log_function,
    log_analysis_file,
    log_result,
    log_vulnerabilities,
    debug,
    info,
    warning,
    error,
    critical,
)


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
        self.config = config
        self.sources = config["sources"]
        self.sinks = config["sinks"]
        self.debug = debug
        self.analyzed_files = set()

        # Global tracking across multiple files
        self.all_functions = {}  # name -> CallGraphNode
        self.all_tainted_vars = {}  # name -> source_info
        self.global_call_graph = {}  # func_name -> list of called funcs

        # Track cross-module imports
        self.module_map = {}  # module_name -> file_path

        # Helper objects for modularized functionality
        self.call_chain_builder = CallChainBuilder(self)
        self.vulnerability_finder = VulnerabilityFinder(self)
        self.utils = TaintAnalysisUtils(self)

    def analyze_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Analyze a file for taint vulnerabilities with enhanced tracking.

        Args:
            file_path: Path to the file to analyze

        Returns:
            List of enhanced vulnerability dictionaries
        """
        if not os.path.exists(file_path):
            if self.debug:
                print(f"❌ Error: File not found: {file_path}")
            return []

        if not file_path.endswith(".py"):
            if self.debug:
                print(f"⚠️ Skipping non-Python file: {file_path}")
            return []

        # Mark file as analyzed
        self.analyzed_files.add(file_path)

        if self.debug:
            print(f"\n🔍 Starting analysis of file: {file_path}")

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
                    print(f"Syntax error in {file_path}: {e}")
                return []

            # Add parent references to nodes
            parent_visitor = ParentNodeVisitor()
            parent_visitor.visit(tree)

            # Visit the AST with enhanced visitor
            visitor = EnhancedTaintAnalysisVisitor(
                parent_map=parent_visitor.parent_map,
                debug_mode=self.debug,
                verbose=False,
                file_path=file_path,
            )
            # Set sources and sinks from the tracker
            visitor.sources = self.sources
            visitor.sinks = self.sinks
            visitor.visit(tree)

            # Update global call graph
            self._update_global_call_graph(visitor)

            # Find vulnerabilities with enhanced tracking
            vulnerabilities = self.vulnerability_finder.find_vulnerabilities(
                visitor, file_path
            )

            # Keep track of reported sink lines from full flows
            reported_sink_lines = {
                vuln.get("sink", {}).get("line", -1) for vuln in vulnerabilities
            }

            # Add new detection logic: treat standalone sinks as potential vulnerabilities
            additional_vulns = self._detect_standalone_sinks(
                visitor, file_path, reported_sink_lines
            )
            vulnerabilities.extend(additional_vulns)

            if self.debug:
                print(f"Enhanced analysis complete for {file_path}")
                print(
                    f"Found {len(vulnerabilities)} vulnerabilities with enhanced tracking"
                )
                print(
                    f"Tracked {len(visitor.def_use_chains)} variables with def-use chains"
                )
                print(
                    f"Identified {len(visitor.data_structures)} complex data structures"
                )

            self.visitor = visitor
            return vulnerabilities

        except Exception as e:
            if self.debug:
                print(f"Error in enhanced analysis for {file_path}: {e}")
                traceback.print_exc()
            return []

    def _update_global_call_graph(self, visitor: EnhancedTaintAnalysisVisitor) -> None:
        """
        Update the global call graph with information from the visitor.

        Args:
            visitor: EnhancedTaintAnalysisVisitor instance
        """
        # Update function information
        for func_name, func_node in visitor.functions.items():
            if func_name in self.all_functions:
                # Merge information if function was seen before
                existing = self.all_functions[func_name]
                if func_node.ast_node:  # Prefer node with AST definition
                    existing.ast_node = func_node.ast_node
                    existing.file_path = func_node.file_path
                    existing.line_no = func_node.line_no

                # Merge callers and callees
                for caller in func_node.callers:
                    existing.add_caller(caller)
                for callee in func_node.callees:
                    existing.add_callee(callee)

                # Update tainted parameters and return status
                existing.tainted_parameters.update(func_node.tainted_parameters)
                existing.return_tainted = (
                    existing.return_tainted or func_node.return_tainted
                )
                existing.return_taint_sources.extend(func_node.return_taint_sources)
            else:
                # Add new function to global tracking
                self.all_functions[func_name] = func_node

        # Update global call graph relationships
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
        Detect standalone sinks as potential vulnerabilities.

        Args:
            visitor: EnhancedTaintAnalysisVisitor instance
            file_path: Path to the analyzed file
            reported_sink_lines: Set of sink line numbers already reported

        Returns:
            List of vulnerability dictionaries for standalone sinks
        """
        standalone_vulnerabilities = []

        if hasattr(visitor, "found_sinks") and visitor.found_sinks:
            if self.debug:
                print(f"Found {len(visitor.found_sinks)} potential sinks")
                # Check the source_lines attribute
                if hasattr(visitor, "source_lines") and visitor.source_lines:
                    print(
                        f"✓ Visitor has source_lines attribute with {len(visitor.source_lines)} lines of source code"
                    )
                else:
                    print(
                        "✗ Visitor does not have source_lines attribute or it is empty"
                    )

            for sink_info in visitor.found_sinks:
                # Create a serializable copy of sink_info, removing the AST node
                serializable_sink = {}
                for key, value in sink_info.items():
                    if key != "node":  # Skip AST node
                        serializable_sink[key] = value

                # Continue processing with the serializable sink_info
                sink_line = serializable_sink.get("line", 0)

                # Check if this sink has already been reported in a full flow
                if sink_line in reported_sink_lines:
                    continue  # Skip if already reported via a full taint flow

                # If this sink hasn't been reported, create a new vulnerability record
                # Create a default "Unknown Source" source
                unknown_source = {
                    "name": "UnknownSource",
                    "line": 0,
                    "col": 0,
                    "context": "auto_detected",
                    "description": "Automatically detected unknown source",
                }

                # Attempt to build a partial call chain based on sink location
                partial_call_chain = self.call_chain_builder.build_enhanced_call_chain(
                    visitor, serializable_sink
                )

                # Create vulnerability record
                sink_vulnerability = {
                    "file": file_path,
                    "rule": f"Potential{serializable_sink.get('vulnerability_type', serializable_sink.get('name', 'Unknown'))}",
                    "source": unknown_source,
                    "sink": serializable_sink,  # Use the serializable version
                    "tainted_variable": "Unknown",
                    "severity": "Medium",  # Default to medium severity
                    "confidence": "Low",  # Confidence is low due to uncertain source
                    "description": f"Potential dangerous operation point {serializable_sink.get('name', 'Unknown')} found, but data source could not be determined",
                    "auto_detected": True,  # Mark as auto-detected vulnerability
                    "call_chain": partial_call_chain,  # Use the generated partial chain
                }

                # Add extra sink-related info if available
                if "tainted_args" in serializable_sink:
                    sink_vulnerability["tainted_arguments"] = serializable_sink[
                        "tainted_args"
                    ]

                standalone_vulnerabilities.append(sink_vulnerability)
                reported_sink_lines.add(sink_line)  # Mark as reported

                if self.debug:
                    print(
                        f"Auto-detected potential vulnerability: {serializable_sink.get('name', 'Unknown')} at line {sink_line}"
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
        all_vulnerabilities = []

        # First pass: analyze each file individually
        for file_path in file_paths:
            if self.debug:
                print(f"Analyzing {file_path}")
            vulnerabilities = self.analyze_file(file_path)
            all_vulnerabilities.extend(vulnerabilities)

        # Second pass: propagate taint across function calls
        if self.debug:
            print("Propagating taint across function calls...")
        self._propagate_taint_across_functions()

        # Third pass: re-analyze files with updated taint information
        additional_vulnerabilities = []
        for file_path in file_paths:
            if self.debug:
                print(f"Re-analyzing {file_path} with cross-function taint information")
            vulnerabilities = self.analyze_file(file_path)

            # Only add new vulnerabilities not in the original set
            for vuln in vulnerabilities:
                if vuln not in all_vulnerabilities:
                    additional_vulnerabilities.append(vuln)

        all_vulnerabilities.extend(additional_vulnerabilities)

        if self.debug:
            print(f"Total vulnerabilities found: {len(all_vulnerabilities)}")

        return all_vulnerabilities

    def _propagate_taint_across_functions(self) -> None:
        """
        Propagate taint information across function calls.
        """
        # Iteratively propagate taint until fixpoint
        changed = True
        iterations = 0
        max_iterations = 10  # Prevent infinite loops

        while changed and iterations < max_iterations:
            iterations += 1
            changed = False

            # For each function that returns tainted data
            for func_name, func_node in self.all_functions.items():
                if func_node.return_tainted:
                    # For each caller of this function
                    for caller in func_node.callers:
                        # Check if caller is not already marked as returning tainted data
                        if not caller.return_tainted:
                            caller.return_tainted = True
                            caller.return_taint_sources.extend(
                                func_node.return_taint_sources
                            )
                            changed = True
                            if self.debug:
                                print(
                                    f"Propagated taint from {func_name} to caller {caller.name}"
                                )

        if self.debug:
            if iterations == max_iterations:
                print(
                    f"Warning: Reached maximum iterations ({max_iterations}) in taint propagation"
                )
            else:
                print(f"Taint propagation converged after {iterations} iterations")

    def check_sink_patterns(self, file_path: str) -> List[Tuple[str, int]]:
        """
        Check for sink patterns in a file.

        Args:
            file_path: Path to the file to check

        Returns:
            List of (pattern, line_number) tuples for sink patterns found
        """
        if not os.path.exists(file_path) or not file_path.endswith(".py"):
            return []

        sink_patterns = []
        for sink in self.sinks:
            if "pattern" in sink:
                sink_patterns.append(sink["pattern"])

        if not sink_patterns:
            return []

        found_patterns = []
        try:
            with open(file_path, "r") as f:
                for i, line in enumerate(f, 1):
                    for pattern in sink_patterns:
                        if pattern in line:
                            found_patterns.append((pattern, i))
                            if self.debug:
                                print(
                                    f"Found sink pattern '{pattern}' in {file_path} at line {i}"
                                )
        except Exception as e:
            if self.debug:
                print(f"Error checking sink patterns in {file_path}: {e}")

        return found_patterns

    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the analysis.

        Returns:
            Dictionary with summary information
        """
        return {
            "files_analyzed": len(self.analyzed_files),
            "functions_analyzed": len(self.all_functions),
            "function_call_relationships": sum(
                len(callees) for callees in self.global_call_graph.values()
            ),
            "functions_returning_tainted_data": sum(
                1 for f in self.all_functions.values() if f.return_tainted
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
        summary = self.get_summary()

        # Call chain statistics
        total_call_steps = 0
        max_call_steps = 0
        min_call_steps = float("inf")
        vuln_with_calls = 0

        # Source-sink statistics
        source_counts = {}
        sink_counts = {}
        source_sink_pairs = {}

        for vuln in vulnerabilities:
            # Count sources
            source_name = vuln.get("source", {}).get("name", "Unknown")
            source_counts[source_name] = source_counts.get(source_name, 0) + 1

            # Count sinks
            sink_name = vuln.get("sink", {}).get("name", "Unknown")
            sink_counts[sink_name] = sink_counts.get(sink_name, 0) + 1

            # Count source-sink pairs
            pair = f"{source_name} -> {sink_name}"
            source_sink_pairs[pair] = source_sink_pairs.get(pair, 0) + 1

            # Call chain statistics
            call_chain = vuln.get("call_chain", [])
            if call_chain:
                vuln_with_calls += 1
                steps = len(call_chain)
                total_call_steps += steps
                max_call_steps = max(max_call_steps, steps)
                min_call_steps = min(min_call_steps, steps)

        # Calculate averages
        avg_call_steps = (
            total_call_steps / vuln_with_calls if vuln_with_calls > 0 else 0
        )

        # Add statistics to summary
        summary.update(
            {
                "vulnerabilities_found": len(vulnerabilities),
                "vulnerabilities_with_call_chains": vuln_with_calls,
                "average_call_chain_length": round(avg_call_steps, 2),
                "max_call_chain_length": max_call_steps,
                "min_call_chain_length": min_call_steps
                if min_call_steps != float("inf")
                else 0,
                "source_counts": source_counts,
                "sink_counts": sink_counts,
                "source_sink_pairs": source_sink_pairs,
            }
        )

        return summary

    @log_function(level="info")
    def print_detailed_vulnerability(self, vulnerability: Dict[str, Any]) -> None:
        """
        Print a detailed vulnerability report with enhanced call chain information.

        Args:
            vulnerability: The vulnerability dictionary
        """
        divider = "=" * 80
        # 使用一个字符串构建器来收集输出，然后一次性输出
        output_lines = []

        output_lines.append("\n" + divider)
        output_lines.append(f"漏洞报告: {vulnerability.get('rule', '未知规则')}")
        output_lines.append(divider)

        # 文件信息
        file_path = vulnerability.get("file", "未知文件")
        output_lines.append(f"文件: {file_path}")

        # 源信息
        source = vulnerability.get("source", {})
        source_name = source.get("name", "未知")
        source_line = source.get("line", 0)
        output_lines.append(f"源: {source_name} 在第 {source_line} 行")

        # 汇聚点信息
        sink = vulnerability.get("sink", {})
        sink_name = sink.get("name", "未知")
        sink_line = sink.get("line", 0)
        output_lines.append(f"汇聚点: {sink_name} 在第 {sink_line} 行")

        # 受污染的变量
        tainted_var = vulnerability.get("tainted_variable", "未知")
        output_lines.append(f"受污染的变量: {tainted_var}")

        # 严重性和可信度
        severity = vulnerability.get("severity", "未知")
        confidence = vulnerability.get("confidence", "未知")
        output_lines.append(f"严重性: {severity}")
        output_lines.append(f"可信度: {confidence}")

        # 描述
        description = vulnerability.get("description", "无可用描述")
        output_lines.append(f"\n描述: {description}")

        # 调用链信息
        call_chain = vulnerability.get("call_chain", [])
        if call_chain:
            output_lines.append("\n调用链:")
            for i, call_item in enumerate(call_chain):
                # 增强的调用链显示
                call_type = call_item.get("type", "unknown")
                call_func = call_item.get("function", "未知")
                call_line = call_item.get("line", 0)
                call_file = call_item.get("file", "未知")

                # 可区分不同类型调用链节点的标题
                title = f"[{i+1}] {call_type.upper()}: {call_func} @ {os.path.basename(call_file)}:{call_line}"
                output_lines.append(f"\n  {title}")

                # 语句 (如果可用)
                if "statement" in call_item:
                    statement = call_item["statement"]
                    output_lines.append(f"      语句: {statement}")

                # 上下文行 (如果可用)
                if "context_lines" in call_item and call_item["context_lines"]:
                    context_start, context_end = call_item["context_lines"]
                    output_lines.append(f"      上下文: 第 {context_start}-{context_end} 行")

                    # 如果有源代码，尝试显示上下文代码
                    if (
                        hasattr(self, "current_file_contents")
                        and self.current_file_contents
                    ):
                        # 从当前文件内容中提取上下文
                        try:
                            context_lines = self.current_file_contents.splitlines()[
                                context_start - 1 : context_end
                            ]
                            if context_lines:
                                output_lines.append("      代码:")
                                for i, line in enumerate(context_lines, context_start):
                                    # 高亮当前行
                                    if i == call_line:
                                        output_lines.append(f"      > {i}: {line}")
                                    else:
                                        output_lines.append(f"        {i}: {line}")
                        except Exception as e:
                            error(f"显示上下文时出错: {str(e)}")

                # 描述
                description = call_item.get("description", "")
                if description:
                    output_lines.append(f"      描述: {description}")

                # 调用信息 (如果可用)
                if "calls" in call_item:
                    output_lines.append("      调用:")
                    for call in call_item["calls"]:
                        func_name = call.get("function", "unknown")
                        statement = call.get("statement", "")
                        output_lines.append(f"        -> {func_name}: {statement}")

        output_lines.append(divider + "\n")

        # 将所有输出作为一个信息日志条目输出
        info("\n".join(output_lines))
