"""
Utility functions for call chain analysis.
"""

import re
from typing import Any, Dict, List, Set, Optional

from lanalyzer.analysis.visitor import EnhancedTaintAnalysisVisitor


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
        根据数据流依赖关系重新排序调用链。
        确保调用链能够准确反映数据如何从源流向汇聚点，即使有步骤出现在不同的函数中。

        Args:
            call_chain: 原始调用链

        Returns:
            重新排序的调用链
        """
        if not call_chain:
            return []

        # 按类型分类节点
        sources = []
        data_flows = []
        sink_containers = []
        sinks = []
        others = []

        for node in call_chain:
            node_type = node.get("type", "")
            if node_type == "source":
                sources.append(node)
            elif node_type == "data_flow":
                data_flows.append(node)
            elif node_type == "sink_container":
                sink_containers.append(node)
            elif node_type == "sink":
                sinks.append(node)
            else:
                others.append(node)

        # 按行号排序源节点和流节点
        sources.sort(key=lambda x: x.get("line", 0))
        data_flows.sort(key=lambda x: x.get("line", 0))

        # 构造新的调用链
        reordered_chain = []

        # 1. 添加源节点
        for node in sources:
            reordered_chain.append(node)

        # 2. 添加数据流节点
        for node in data_flows:
            reordered_chain.append(node)

        # 3. 如果有其他节点，保持它们的相对顺序
        for node in others:
            reordered_chain.append(node)

        # 4. 添加包含sink的容器节点
        for node in sink_containers:
            reordered_chain.append(node)

        # 5. 最后添加sink节点
        for node in sinks:
            reordered_chain.append(node)

        # 确保每个节点的唯一性（防止重复）
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
        从配置文件获取对应类型的模式

        Args:
            pattern_type: 'sources', 'sinks', 或 'sanitizers'

        Returns:
            模式列表
        """
        patterns = []
        if not hasattr(self.tracker, "config"):
            if self.debug:
                print(f"[DEBUG] No configuration found in tracker")
            return patterns

        config = self.tracker.config

        if not isinstance(config, dict):
            if self.debug:
                print(f"[DEBUG] Configuration is not a dictionary")
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
            print(f"[DEBUG] Extracted {len(patterns)} patterns for {pattern_type}")

        return patterns

    def extract_sink_parameters(self, sink_code: str) -> List[str]:
        """
        根据配置的sink模式提取参数表达式

        Args:
            sink_code: 汇聚点代码行

        Returns:
            参数表达式列表
        """
        sink_patterns = self.get_patterns_from_config("sinks")
        sink_arg_expressions = []

        # 如果没有从配置中获取到模式，使用默认的模式
        if not sink_patterns:
            default_pattern = r"(?:pickle|cloudpickle|yaml|json)\.loads\((.*?)\)"
            matches = re.search(default_pattern, sink_code)
            if matches:
                sink_arg_expressions.append(matches.group(1).strip())
            return sink_arg_expressions

        for pattern in sink_patterns:
            # 转换通配符模式为正则表达式
            if "*" in pattern:
                regex_pattern = pattern.replace(".", "\\.").replace("*", ".*?")
                # 构建正则提取参数的表达式
                full_pattern = f"({regex_pattern})\\s*\\((.*?)\\)"
                matches = re.search(full_pattern, sink_code)
                if matches:
                    sink_arg_expressions.append(matches.group(2).strip())
            else:
                # 处理精确匹配模式
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
        合并数据流和控制流调用链

        Args:
            data_flow_chain: 数据流调用链
            control_flow_chain: 控制流调用链

        Returns:
            合并后的调用链
        """
        if not control_flow_chain:
            return data_flow_chain

        if not data_flow_chain:
            return control_flow_chain

        # 对节点进行分类
        entry_points = []
        control_flows = []
        sources = []
        data_flows = []
        sink_containers = []
        sinks = []

        # 从控制流链中提取节点
        for node in control_flow_chain:
            node_type = node.get("type", "")
            if node_type == "entry_point":
                entry_points.append(node)
            elif node_type == "control_flow":
                control_flows.append(node)
            elif node_type == "sink_container":
                # 检查是否已经在数据流中
                if not any(n.get("type") == "sink_container" for n in data_flow_chain):
                    sink_containers.append(node)

        # 从数据流链中提取节点
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

        # 去重并按逻辑顺序合并
        merged_chain = []

        # 1. 添加入口点
        for node in entry_points:
            merged_chain.append(node)

        # 2. 添加控制流节点
        for node in control_flows:
            if not any(
                n.get("line") == node.get("line")
                and n.get("function") == node.get("function")
                for n in merged_chain
            ):
                merged_chain.append(node)

        # 3. 添加源节点
        for node in sources:
            if not any(
                n.get("line") == node.get("line")
                and n.get("statement") == node.get("statement")
                for n in merged_chain
            ):
                merged_chain.append(node)

        # 4. 添加数据流节点
        for node in data_flows:
            if not any(
                n.get("line") == node.get("line")
                and n.get("statement") == node.get("statement")
                for n in merged_chain
            ):
                merged_chain.append(node)

        # 5. 添加sink容器节点（确保只添加一次）
        for node in sink_containers:
            if not any(
                n.get("type") == "sink_container"
                and n.get("function") == node.get("function")
                for n in merged_chain
            ):
                merged_chain.append(node)

        # 6. 添加sink节点
        for node in sinks:
            if not any(
                n.get("line") == node.get("line") and n.get("type") == "sink"
                for n in merged_chain
            ):
                merged_chain.append(node)

        # 按照行号排序，确保调用链顺序合理
        merged_chain.sort(key=lambda x: x.get("line", 0))

        if self.debug:
            print(
                f"[DEBUG] Merged control flow ({len(control_flow_chain)} nodes) and data flow ({len(data_flow_chain)} nodes) into {len(merged_chain)} nodes"
            )

        return merged_chain
