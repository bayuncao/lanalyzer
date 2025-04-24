"""
Enhanced taint tracker implementation.
"""

import ast
import os
import traceback
import re
from typing import Any, Dict, List, Tuple, Set, Optional

from lanalyzer.analysis.enhanced.ast_parser import ParentNodeVisitor

from .visitor import EnhancedTaintAnalysisVisitor


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
                print(f"❌ 错误: 文件不存在: {file_path}")
            return []

        if not file_path.endswith(".py"):
            if self.debug:
                print(f"⚠️ 跳过非Python文件: {file_path}")
            return []

        # Mark file as analyzed
        self.analyzed_files.add(file_path)

        if self.debug:
            print(f"\n🔍 开始分析文件: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()

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
                debug=self.debug,
                verbose=False,
                file_path=file_path,
            )
            # Set sources and sinks from the tracker
            visitor.sources = self.sources
            visitor.sinks = self.sinks
            visitor.visit(tree)

            # Update global call graph
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

            # Find vulnerabilities with enhanced tracking
            vulnerabilities = self._find_enhanced_vulnerabilities(visitor, file_path)

            # Keep track of reported sink lines from full flows
            reported_sink_lines = {vuln.get("sink", {}).get("line", -1) for vuln in vulnerabilities}

            # 添加新的检测逻辑：单独的汇点也视为潜在漏洞
            if hasattr(visitor, "found_sinks") and visitor.found_sinks:
                if self.debug:
                    print(f"发现 {len(visitor.found_sinks)} 个潜在汇点")
                    # 检查source_lines属性
                    if hasattr(visitor, 'source_lines') and visitor.source_lines:
                        print(f"✓ visitor有source_lines属性，包含 {len(visitor.source_lines)} 行源代码")
                    else:
                        print(f"✗ visitor没有source_lines属性或为空")
                    
                for sink_info in visitor.found_sinks:
                    # 创建sink_info的可序列化副本，移除AST节点
                    serializable_sink = {}
                    for key, value in sink_info.items():
                        if key != "node":  # 跳过AST节点
                            serializable_sink[key] = value
                    
                    # 使用可序列化的sink_info继续处理
                    sink_line = serializable_sink.get("line", 0)
                    
                    # 检查此汇点是否已在完整流程中报告
                    if sink_line in reported_sink_lines:
                        continue # Skip if already reported via a full taint flow

                    # 如果这个汇点尚未被报告，创建一个新的漏洞记录
                    # (This block is reached only if the sink wasn't part of a full flow)
                    # 创建一个默认的"未知来源"源点
                    unknown_source = {
                        "name": "UnknownSource",
                        "line": 0,
                        "col": 0,
                        "context": "auto_detected",
                        "description": "自动检测到的未知来源"
                    }

                    # Attempt to build a partial call chain based on sink location
                    partial_call_chain = self._build_partial_call_chain_for_sink(visitor, serializable_sink)
                    
                    # 创建漏洞记录
                    sink_vulnerability = {
                        "file": file_path,
                        "rule": f"潜在{serializable_sink.get('vulnerability_type', serializable_sink.get('name', 'Unknown'))}",
                        "source": unknown_source,
                        "sink": serializable_sink,  # 使用可序列化的版本
                        "tainted_variable": "未知",
                        "severity": "中",  # 默认为中等严重性
                        "confidence": "低",  # 由于没有确定的源点，信心值较低
                        "description": f"发现潜在危险操作点 {serializable_sink.get('name', 'Unknown')}，但未能确定数据来源",
                        "auto_detected": True,  # 标记为自动检测的漏洞
                        "propagation_path": [],  # 没有传播路径 (as source is unknown)
                        "call_chain": partial_call_chain # Use the generated partial chain
                    }
                    
                    # 添加额外的汇点相关信息（如果有）
                    if "tainted_args" in serializable_sink:
                        sink_vulnerability["tainted_arguments"] = serializable_sink["tainted_args"]
                    
                    vulnerabilities.append(sink_vulnerability)
                    reported_sink_lines.add(sink_line) # Mark as reported
                    
                    if self.debug:
                        print(f"自动检测到潜在漏洞: {serializable_sink.get('name', 'Unknown')} 在行 {sink_line}")

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

            self.visitor = visitor  # 这行代码可能在原实现中缺失或位置不当
            return vulnerabilities

        except Exception as e:
            if self.debug:
                print(f"Error in enhanced analysis for {file_path}: {e}")
                traceback.print_exc()
            return []

    def _find_enhanced_vulnerabilities(
        self, visitor: EnhancedTaintAnalysisVisitor, file_path: str
    ) -> List[Dict[str, Any]]:
        """
        Find vulnerabilities using enhanced tracking information.

        Args:
            visitor: EnhancedTaintAnalysisVisitor instance
            file_path: Path to the analyzed file

        Returns:
            List of enhanced vulnerability dictionaries
        """
        vulnerabilities = []

        for sink in visitor.found_sinks:
            for tainted_arg in sink.get("tainted_args", []):
                arg_name, source_info = tainted_arg

                # Find matching rule
                for rule in self.config.get("rules", []):
                    source_name = source_info["name"]
                    sink_name = sink["name"]

                    if self._source_matches_rule(
                        source_name, rule
                    ) and self._sink_matches_rule(sink_name, rule):
                        # Get taint propagation chain for this vulnerability
                        propagation_chain = []
                        if isinstance(arg_name, str):
                            # Handle direct call arguments
                            if arg_name.startswith("direct_call_"):
                                # For direct call arguments, create a basic propagation chain
                                propagation_chain = [
                                    {
                                        "step_no": 1,
                                        "operation": "DirectCall",
                                        "description": f"Direct call from source to sink at line {sink.get('line', 0)}",
                                        "line": sink.get("line", 0),
                                        "var_name": arg_name,
                                    }
                                ]
                            else:
                                # For named arguments, get full propagation chain
                                if "=" in arg_name:
                                    # Handle keyword arguments
                                    parts = arg_name.split("=")
                                    arg_base_name = parts[0]
                                    value_name = parts[1]

                                    # Get chain for the value
                                    if value_name in visitor.variable_taint:
                                        propagation_chain = (
                                            visitor.get_taint_propagation_chain(
                                                value_name
                                            )
                                        )
                                        # Add parameter binding step
                                        propagation_chain.append(
                                            {
                                                "step_no": len(propagation_chain) + 1,
                                                "operation": "ParameterBinding",
                                                "description": f"Value '{value_name}' bound to parameter '{arg_base_name}' at line {sink.get('line', 0)}",
                                                "line": sink.get("line", 0),
                                                "var_name": arg_name,
                                            }
                                        )
                                    # Check data structures too
                                    elif value_name in visitor.data_structures:
                                        ds_chain = visitor.data_structures[
                                            value_name
                                        ].get_propagation_chain()
                                        propagation_chain.extend(ds_chain)
                                        # Add parameter binding step
                                        propagation_chain.append(
                                            {
                                                "step_no": len(propagation_chain) + 1,
                                                "operation": "DataStructureBinding",
                                                "description": f"Data structure '{value_name}' bound to parameter '{arg_base_name}' at line {sink.get('line', 0)}",
                                                "line": sink.get("line", 0),
                                                "var_name": arg_name,
                                            }
                                        )
                                else:
                                    # Regular variable
                                    arg_base_name = arg_name
                                    propagation_chain = (
                                        visitor.get_taint_propagation_chain(
                                            arg_base_name
                                        )
                                    )

                                    # Check for data structures as well
                                    if (
                                        arg_base_name in visitor.data_structures
                                        and not propagation_chain
                                    ):
                                        ds_chain = visitor.data_structures[
                                            arg_base_name
                                        ].get_propagation_chain()
                                        propagation_chain.extend(ds_chain)

                        # Get detailed call chain
                        call_chain = self._get_detailed_call_chain(
                            sink, visitor, source_info
                        )

                        # Format message with the actual source name
                        message = rule.get(
                            "message",
                            f"Tainted data from {source_name} flows to {sink_name}",
                        )
                        message = message.replace("{source}", source_name)

                        # Add a final step in the propagation chain showing sink usage
                        if propagation_chain:
                            propagation_chain.append(
                                {
                                    "step_no": len(propagation_chain) + 1,
                                    "operation": "SinkUsage",
                                    "description": f"Tainted data flows to {sink_name} sink at line {sink.get('line', 0)}",
                                    "line": sink.get("line", 0),
                                    "var_name": arg_name,
                                }
                            )

                        # Build enhanced vulnerability info
                        vulnerability = {
                            "rule": rule.get("name", "UnnamedRule"),
                            "message": message,
                            "file": file_path,
                            "source": {
                                "name": source_name,
                                "line": source_info.get("line", 0),
                                "col": source_info.get("col", 0),
                            },
                            "sink": {
                                "name": sink_name,
                                "line": sink.get("line", 0),
                                "col": sink.get("col", 0),
                            },
                            "tainted_variable": arg_name,
                            "propagation_chain": propagation_chain,
                            "call_chain": call_chain,
                        }

                        vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _source_matches_rule(self, source_name: str, rule: Dict[str, Any]) -> bool:
        """
        Check if a source matches a rule.

        Args:
            source_name: Name of the source
            rule: Rule dictionary

        Returns:
            True if the source matches the rule, False otherwise
        """
        sources = rule.get("sources", [])
        return source_name in sources or "any" in sources

    def _sink_matches_rule(self, sink_name: str, rule: Dict[str, Any]) -> bool:
        """
        Check if a sink matches a rule.

        Args:
            sink_name: Name of the sink
            rule: Rule dictionary

        Returns:
            True if the sink matches the rule, False otherwise
        """
        sinks = rule.get("sinks", [])
        return sink_name in sinks or "any" in sinks

    def _get_detailed_call_chain(
        self,
        sink: Dict[str, Any],
        visitor: EnhancedTaintAnalysisVisitor,
        source_info: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        获取从源点到汇点的详细函数调用链。

        Args:
            sink: 汇点字典
            visitor: EnhancedTaintAnalysisVisitor实例
            source_info: 源点信息字典

        Returns:
            包含详细函数调用链信息的字典列表
        """
        call_chain = []
        source_line = source_info.get("line", 0)
        sink_line = sink.get("line", 0)
        source_name = source_info.get("name", "Unknown")
        sink_name = sink.get("name", "Unknown")

        if self.debug:
            print(f"构建从源点 {source_name}(行 {source_line}) 到汇点 {sink_name}(行 {sink_line}) 的调用链")

        # 1. 找到包含源点的函数
        source_func = None
        for func_name, func_node in visitor.functions.items():
            if func_node.line_no <= source_line <= func_node.end_line_no:
                source_func = func_node
                break

        # 2. 找到包含汇点的函数
        sink_func = None
        for func_name, func_node in visitor.functions.items():
            if func_node.line_no <= sink_line <= func_node.end_line_no:
                sink_func = func_node
                break

        if self.debug:
            if source_func:
                print(f"找到源点函数: {source_func.name} (行 {source_func.line_no}-{source_func.end_line_no})")
            else:
                print(f"未找到包含源点(行 {source_line})的函数")
                
            if sink_func:
                print(f"找到汇点函数: {sink_func.name} (行 {sink_func.line_no}-{sink_func.end_line_no})")
            else:
                print(f"未找到包含汇点(行 {sink_line})的函数")

        # 3. 如果源点和汇点是同一个函数，直接返回该函数信息
        if source_func and sink_func and source_func.name == sink_func.name:
            func_info = {
                "function": source_func.name,
                "file": source_func.file_path,
                "line": source_func.line_no,
                "type": "source+sink",
                "description": f"同时包含源点 {source_name}(行 {source_line}) 和汇点 {sink_name}(行 {sink_line})"
            }
            call_chain.append(func_info)
            return call_chain

        # 4. 构建从汇点到源点的完整调用链
        if source_func and sink_func:
            # 使用广度优先搜索(BFS)查找从源点函数到汇点函数的路径
            queue = [(source_func, [source_func])]  # (当前节点, 路径)
            visited = {source_func.name}
            max_depth = 20  # 防止过深搜索
            found_path = None

            while queue and not found_path:
                current, path = queue.pop(0)
                
                # 检查当前节点的被调用者
                for callee in current.callees:
                    if callee.name == sink_func.name:
                        # 找到路径
                        found_path = path + [sink_func]
                        break
                    
                    if callee.name not in visited and len(path) < max_depth:
                        visited.add(callee.name)
                        queue.append((callee, path + [callee]))
            
            # 如果找到路径，构建调用链
            if found_path:
                for i, func in enumerate(found_path):
                    node_type = "intermediate"
                    description = "调用链中的中间函数"
                    
                    if i == 0:
                        node_type = "source"
                        description = f"包含源点 {source_name} 在行 {source_line}"
                    elif i == len(found_path) - 1:
                        node_type = "sink"
                        description = f"包含汇点 {sink_name} 在行 {sink_line}"
                    
                    func_info = {
                        "function": func.name,
                        "file": func.file_path,
                        "line": func.line_no,
                        "type": node_type,
                        "description": description
                    }
                    call_chain.append(func_info)
                
                return call_chain
            
            # 如果找不到直接路径，尝试查找共同的调用者
            if not found_path and self.debug:
                print("未找到直接路径，尝试查找共同的调用者...")

            # 构建反向调用图(从被调用者到调用者)
            reverse_call_graph = {}
            for func_name, func_node in visitor.functions.items():
                reverse_call_graph[func_name] = []
                
            for func_name, func_node in visitor.functions.items():
                for callee in func_node.callees:
                    if callee.name not in reverse_call_graph:
                        reverse_call_graph[callee.name] = []
                    reverse_call_graph[callee.name].append(func_name)
            
            # 使用BFS查找源点函数和汇点函数的共同调用者
            source_callers = self._find_callers(source_func.name, reverse_call_graph, max_depth)
            sink_callers = self._find_callers(sink_func.name, reverse_call_graph, max_depth)
            
            common_callers = source_callers.intersection(sink_callers)
            
            if common_callers and self.debug:
                print(f"找到共同调用者: {common_callers}")
            
            # 如果找到共同调用者，构建路径
            if common_callers:
                # 选择一个共同调用者
                common_caller = next(iter(common_callers))
                common_caller_node = None
                
                for func_name, func_node in visitor.functions.items():
                    if func_name == common_caller:
                        common_caller_node = func_node
                        break
                
                if common_caller_node:
                    # 源点函数 -> 共同调用者 -> 汇点函数
                    call_chain = [
                        {
                            "function": source_func.name,
                            "file": source_func.file_path,
                            "line": source_func.line_no,
                            "type": "source",
                            "description": f"包含源点 {source_name} 在行 {source_line}"
                        },
                        {
                            "function": common_caller_node.name,
                            "file": common_caller_node.file_path,
                            "line": common_caller_node.line_no,
                            "type": "intermediate",
                            "description": "源点和汇点的共同调用者"
                        },
                        {
                            "function": sink_func.name,
                            "file": sink_func.file_path,
                            "line": sink_func.line_no,
                            "type": "sink",
                            "description": f"包含汇点 {sink_name} 在行 {sink_line}"
                        }
                    ]
                    return call_chain

        # 5. 如果无法构建完整调用链，但源点函数或汇点函数存在，则添加它们
        if source_func:
            source_func_info = {
                "function": source_func.name,
                "file": source_func.file_path,
                "line": source_func.line_no,
                "type": "source",
                "description": f"包含源点 {source_name} 在行 {source_line}"
            }
            call_chain.append(source_func_info)
            
        if sink_func:
            sink_func_info = {
                "function": sink_func.name,
                "file": sink_func.file_path,
                "line": sink_func.line_no,
                "type": "sink",
                "description": f"包含汇点 {sink_name} 在行 {sink_line}"
            }
            # 避免重复添加(如果源点和汇点在同一函数但之前未检测到)
            if not call_chain or call_chain[0]["function"] != sink_func.name:
                call_chain.append(sink_func_info)

        return call_chain
        
    def _find_callers(self, func_name: str, reverse_call_graph: Dict[str, List[str]], max_depth: int) -> Set[str]:
        """
        使用BFS找到调用指定函数的所有函数。

        Args:
            func_name: 要查找调用者的函数名
            reverse_call_graph: 反向调用图
            max_depth: 最大搜索深度

        Returns:
            调用该函数的函数名集合
        """
        callers = set()
        visited = {func_name}
        queue = [(func_name, 0)]  # (函数名, 深度)
        
        while queue:
            current, depth = queue.pop(0)
            
            if depth >= max_depth:
                continue
                
            # 获取当前函数的所有调用者
            current_callers = reverse_call_graph.get(current, [])
            
            for caller in current_callers:
                callers.add(caller)
                
                if caller not in visited:
                    visited.add(caller)
                    queue.append((caller, depth + 1))
                    
        return callers

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
        Get a detailed summary of the analysis with statistics about propagation chains.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Dictionary with detailed summary information
        """
        # Basic summary
        summary = self.get_summary()

        # Propagation statistics
        total_prop_steps = 0
        max_prop_steps = 0
        min_prop_steps = float("inf")
        vuln_with_prop = 0

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

            # Propagation statistics
            prop_chain = vuln.get("propagation_chain", [])
            if prop_chain:
                vuln_with_prop += 1
                steps = len(prop_chain)
                total_prop_steps += steps
                max_prop_steps = max(max_prop_steps, steps)
                min_prop_steps = min(min_prop_steps, steps)

            # Call chain statistics
            call_chain = vuln.get("call_chain", [])
            if call_chain:
                vuln_with_calls += 1
                steps = len(call_chain)
                total_call_steps += steps
                max_call_steps = max(max_call_steps, steps)
                min_call_steps = min(min_call_steps, steps)

        # Calculate averages
        avg_prop_steps = total_prop_steps / vuln_with_prop if vuln_with_prop > 0 else 0
        avg_call_steps = (
            total_call_steps / vuln_with_calls if vuln_with_calls > 0 else 0
        )

        # Add statistics to summary
        summary.update(
            {
                "vulnerabilities_found": len(vulnerabilities),
                "vulnerabilities_with_propagation": vuln_with_prop,
                "average_propagation_steps": round(avg_prop_steps, 2),
                "max_propagation_steps": max_prop_steps,
                "min_propagation_steps": min_prop_steps
                if min_prop_steps != float("inf")
                else 0,
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

    def print_detailed_vulnerability(self, vulnerability: Dict[str, Any]) -> None:
        """
        Print detailed information about a vulnerability.
        
        Args:
            vulnerability: Vulnerability dictionary
        """
        print("\n" + "=" * 80)
        print(f"VULNERABILITY: {vulnerability.get('rule', 'Unnamed Rule')}")
        print(f"Message: {vulnerability.get('message', 'No message')}")
        print(f"File: {vulnerability.get('file', 'Unknown file')}")
        print("-" * 80)

        # Source information
        source = vulnerability.get("source", {})
        print(
            f"SOURCE: {source.get('name', 'Unknown')} at line {source.get('line', 0)}"
        )

        # Sink information
        sink = vulnerability.get("sink", {})
        print(f"SINK: {sink.get('name', 'Unknown')} at line {sink.get('line', 0)}")

        # Tainted variable
        print(f"TAINTED VARIABLE: {vulnerability.get('tainted_variable', 'Unknown')}")
        print("-" * 80)

        # Propagation chain
        prop_chain = vulnerability.get("propagation_chain", [])
        if prop_chain:
            print("PROPAGATION CHAIN:")
            for step in prop_chain:
                step_no = step.get("step_no", "")
                op = step.get("operation", "Unknown")
                desc = step.get("description", "No description")
                line = step.get("line", 0)
                var = step.get("var_name", "")

                # Format the step
                step_str = f"{step_no}. " if step_no else ""
                step_str += f"[{op}] "
                step_str += desc
                if line:
                    step_str += f" (line {line})"
                if var and var not in desc:
                    step_str += f" - {var}"

                print(f"  {step_str}")
        else:
            print("PROPAGATION CHAIN: None")

        print("-" * 80)

        # Call chain
        call_chain = vulnerability.get("call_chain", [])
        if call_chain:
            print("CALL CHAIN:")
            for i, call in enumerate(call_chain):
                func = call.get("function", "Unknown")
                file = call.get("file", "Unknown file")
                line = call.get("line", 0)
                call_type = call.get("type", "Unknown")
                desc = call.get("description", "")

                # Format the call
                type_display = call_type.upper()
                if call_type == "sink_location":
                    type_display = "SINK LOCATION"
                elif call_type == "source":
                    type_display = "SOURCE LOCATION"
                elif call_type == "intermediate":
                    type_display = "INTERMEDIATE CALL"

                call_str = f"{i+1}. [{type_display}] {func} in {file}:{line}"
                if desc:
                    call_str += f" - {desc}"

                print(f"  {call_str}")
        else:
            print("CALL CHAIN: None")

        print("=" * 80)

        # 检查是否是自动检测的漏洞
        if vulnerability.get("auto_detected", False):
            print("  🤖 自动检测: 是 (基于单独的汇点检测)")
            print(f"  ⚠️ 置信度: {vulnerability.get('confidence', '低')}")
            print("  📝 说明: 此漏洞是基于发现的危险操作点自动生成的，没有确定的数据来源")

    def _build_partial_call_chain_for_sink(
        self, visitor: EnhancedTaintAnalysisVisitor, sink_info: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        构建更完整的调用链，即使在没有明确源点的情况下也能提供丰富的调用上下文。
        这用于自动检测的漏洞，其中无法确定数据的完整来源路径。

        Args:
            visitor: 包含分析结果的访问器实例
            sink_info: 汇点信息字典

        Returns:
            表示调用链的字典列表
        """
        call_chain = []
        sink_line = sink_info.get("line", 0)
        sink_name = sink_info.get("name", "Unknown Sink")
        vulnerability_type = sink_info.get("vulnerability_type", f"{sink_name} Vulnerability")

        if self.debug:
            print(f"[DEBUG] 构建汇点 '{sink_name}' (行 {sink_line}) 的调用链")

        if not sink_line:
            if self.debug:
                print("[DEBUG] 汇点行号为0或缺失")
            return []

        # 步骤1：找到包含汇点的函数
        sink_function_node = self._find_function_containing_line(visitor, sink_line)
        
        # 验证visitor是否有source_lines属性
        has_source_lines = hasattr(visitor, 'source_lines') and visitor.source_lines
        if self.debug:
            if has_source_lines:
                print(f"[DEBUG] visitor有source_lines属性，共 {len(visitor.source_lines)} 行")
            else:
                print(f"[DEBUG] ⚠️ _build_partial_call_chain_for_sink中发现visitor没有source_lines属性!")
                
        # 步骤2：查找直接汇点操作（实际的危险调用）
        sink_operation = self._extract_operation_at_line(visitor, sink_line)
        if sink_operation:
            # 如果发现了直接操作，添加为调用链的第一个元素
            call_chain.append({
                "function": sink_operation,
                "file": visitor.file_path,
                "line": sink_line,
                "type": "sink",
                "description": f"不安全的 {sink_name} 操作，可能导致 {vulnerability_type}"
            })
        
        # 步骤3：添加包含汇点的函数
        if sink_function_node:
            # 检查是否已经添加了同名函数，避免重复
            if not call_chain or call_chain[0]["function"] != sink_function_node.name:
                file_path = getattr(sink_function_node, 'file_path', visitor.file_path)
                sink_func_info = {
                    "function": sink_function_node.name,
                    "file": file_path,
                    "line": sink_function_node.line_no,
                    "type": "sink_container",
                    "description": f"包含汇点 {sink_name} 的函数，在行 {sink_line}"
                }
                call_chain.append(sink_func_info)
        
        # 步骤4：查找有类似功能的相关函数
        related_functions = self._find_related_functions(visitor, sink_name)
        for related_func in related_functions:
            # 确保不添加重复的函数
            if all(entry["function"] != related_func.name for entry in call_chain):
                related_info = {
                    "function": related_func.name,
                    "file": related_func.file_path,
                    "line": related_func.line_no,
                    "type": "related_path",
                    "description": f"使用了类似的不安全技术的相关函数"
                }
                call_chain.append(related_info)
        
        # 步骤5：查找调用者函数（谁调用了包含汇点的函数）
        if sink_function_node and sink_function_node.callers:
            # 仅添加一个主要调用者，避免链条过长
            caller = sink_function_node.callers[0]
            if all(entry["function"] != caller.name for entry in call_chain):
                caller_info = {
                    "function": caller.name,
                    "file": caller.file_path,
                    "line": caller.line_no,
                    "type": "intermediate",
                    "description": f"调用了包含汇点的函数 {sink_function_node.name}"
                }
                call_chain.append(caller_info)

        if self.debug:
            print(f"[DEBUG] 构建了包含 {len(call_chain)} 个节点的调用链")
            
        return call_chain

    def _find_function_containing_line(
        self, visitor: EnhancedTaintAnalysisVisitor, line: int
    ) -> Optional[Any]:
        """
        查找包含指定行的函数节点。

        Args:
            visitor: 访问器实例
            line: 行号

        Returns:
            包含该行的函数节点，如果未找到则返回None
        """
        for func_name, func_node in visitor.functions.items():
            # 确保节点有必要的属性
            if not hasattr(func_node, 'line_no') or not hasattr(func_node, 'end_line_no'):
                continue
            
            # 检查行号是否有效
            if not isinstance(func_node.line_no, int) or not isinstance(func_node.end_line_no, int):
                continue
                
            # 检查行是否在函数范围内
            if func_node.line_no <= line <= func_node.end_line_no:
                return func_node
                
        return None
        
    def _extract_operation_at_line(
        self, visitor: EnhancedTaintAnalysisVisitor, line: int
    ) -> Optional[str]:
        """
        尝试提取指定行的实际操作名称。
        
        Args:
            visitor: 访问器实例
            line: 行号
            
        Returns:
            操作名称，如未找到则返回None
        """
        # 检查是否有原始代码可用
        if not hasattr(visitor, 'source_lines') or not visitor.source_lines:
            if self.debug:
                print(f"[警告] visitor没有source_lines属性或属性为空，无法提取行 {line} 的操作")
            return None
            
        # 确保行号在有效范围内
        if line <= 0 or line > len(visitor.source_lines):
            if self.debug:
                print(f"[警告] 行号 {line} 超出了源码范围 (1-{len(visitor.source_lines)})")
            return None
            
        # 获取行内容
        line_content = visitor.source_lines[line-1].strip()
        
        # 常见的危险函数名称模式
        dangerous_patterns = {
            "PickleDeserialization": ["pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load"],
            "CommandExecution": ["os.system", "subprocess.run", "subprocess.Popen", "exec(", "eval("],
            "SQLInjection": ["execute(", "executemany(", "cursor.execute", "raw_connection"],
            "PathTraversal": ["open(", "os.path.join", "os.makedirs", "os.listdir"],
            "XSS": ["render_template", "render", "html"]
        }
        
        # 尝试找到匹配的危险模式
        sink_type = None
        for sink_name, patterns in dangerous_patterns.items():
            for pattern in patterns:
                if pattern in line_content:
                    sink_type = pattern
                    if self.debug:
                        print(f"[发现] 在行 {line} 找到危险模式: {pattern}")
                    break
            if sink_type:
                break
                
        return sink_type

    def _find_related_functions(
        self, visitor: EnhancedTaintAnalysisVisitor, sink_name: str
    ) -> List[Any]:
        """
        查找与给定汇点相关的函数。
        
        Args:
            visitor: 访问器实例
            sink_name: 汇点名称
            
        Returns:
            相关函数节点列表
        """
        related_functions = []
        
        # 1. 使用配置文件中的sink定义查找相关函数模式
        related_patterns = []
        
        # 从配置文件中查找与sink_name相关的模式
        for sink in self.sinks:
            if sink.get("name") == sink_name:
                # 使用sink的patterns作为相关函数查找的基础
                for pattern in sink.get("patterns", []):
                    # 从pattern中提取基本函数名部分
                    if '.' in pattern:
                        func_part = pattern.split('.')[-1]
                        related_patterns.append(func_part)
                    elif '(' in pattern:
                        func_part = pattern.split('(')[0]
                        related_patterns.append(func_part)
                    else:
                        related_patterns.append(pattern)
                break
                
        # 如果未在配置中找到相关模式，使用汇点名称本身作为依据
        if not related_patterns:
            # 使用sink_name的单词作为搜索模式
            words = re.findall(r'[A-Za-z]+', sink_name)
            for word in words:
                if len(word) > 3:  # 只使用较长的词以避免太短的词导致误匹配
                    related_patterns.append(word.lower())
                    
        # 2. 通过AST分析查找相似的函数
        # 首先查找与模式名称相似的函数
        for func_name, func_node in visitor.functions.items():
            for pattern in related_patterns:
                # 检查函数名是否包含pattern（不区分大小写）
                if pattern.lower() in func_name.lower():
                    related_functions.append(func_node)
                    break
                    
        # 3. 如果是内置的危险模式，添加相关函数
        if "pickle" in sink_name.lower() or "deseriali" in sink_name.lower():
            for func_name, func_node in visitor.functions.items():
                if any(term in func_name.lower() for term in ["load", "dump", "serial", "deserial", "broadcast", "object"]):
                    if func_node not in related_functions:
                        related_functions.append(func_node)
        elif "command" in sink_name.lower() or "exec" in sink_name.lower():
            for func_name, func_node in visitor.functions.items():
                if any(term in func_name.lower() for term in ["run", "exec", "command", "system", "popen", "process"]):
                    if func_node not in related_functions:
                        related_functions.append(func_node)
        elif "sql" in sink_name.lower() or "inject" in sink_name.lower():
            for func_name, func_node in visitor.functions.items():
                if any(term in func_name.lower() for term in ["query", "sql", "execute", "db", "database"]):
                    if func_node not in related_functions:
                        related_functions.append(func_node)
        elif "path" in sink_name.lower() or "file" in sink_name.lower() or "traversal" in sink_name.lower():
            for func_name, func_node in visitor.functions.items():
                if any(term in func_name.lower() for term in ["file", "path", "read", "write", "open", "directory"]):
                    if func_node not in related_functions:
                        related_functions.append(func_node)
                    
        # 4. 查找调用相似函数的函数
        call_related_functions = []
        for func_node in list(related_functions):  # 使用副本以避免在迭代时修改
            # 查找调用当前函数的其他函数
            for caller in func_node.callers:
                if caller not in related_functions and caller not in call_related_functions:
                    call_related_functions.append(caller)
                    
        # 合并直接相关函数和调用关系相关函数
        related_functions.extend(call_related_functions)
                    
        # 5. 限制返回数量，避免结果过于冗长
        return related_functions[:5]
