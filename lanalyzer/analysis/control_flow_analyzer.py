"""
Control flow analysis for taint analysis call chains.

This module analyzes control flow from entry points to taint sinks by:
1. Using AST to build function call graphs
2. Identifying self.method() style method calls
3. Tracing paths from entry points to sink functions
4. Constructing detailed call chains with source code context
"""

import re
from typing import Any, Dict, List, Set, Optional

from lanalyzer.analysis.visitor import EnhancedTaintAnalysisVisitor


class ControlFlowAnalyzer:
    """Analyze control flow from entry points to taint sinks."""

    def __init__(self, builder):
        """Initialize with reference to parent builder."""
        self.builder = builder
        self.tracker = builder.tracker
        self.debug = builder.debug
        # 加载配置的重要方法名称
        self.key_method_names = self._load_key_method_names()

    def _load_key_method_names(self):
        """从配置文件加载关键方法名称"""
        # 初始化为空配置，不使用任何默认值
        key_methods = {"entry_methods": [], "important_methods": []}

        # 从配置中加载
        config = self.tracker.config
        if isinstance(config, dict) and "control_flow" in config:
            control_flow_config = config["control_flow"]

            # 加载入口方法
            if "key_method_names" in control_flow_config and isinstance(
                control_flow_config["key_method_names"], dict
            ):
                key_method_config = control_flow_config["key_method_names"]

                # 读取入口方法名
                if "entry_methods" in key_method_config and isinstance(
                    key_method_config["entry_methods"], list
                ):
                    key_methods["entry_methods"] = key_method_config["entry_methods"]

                # 读取重要方法名
                if "important_methods" in key_method_config and isinstance(
                    key_method_config["important_methods"], list
                ):
                    key_methods["important_methods"] = key_method_config[
                        "important_methods"
                    ]

        if self.debug:
            print(f"[DEBUG] Loaded key method names from config: {key_methods}")

        return key_methods

    def build_control_flow_chain(
        self, visitor: EnhancedTaintAnalysisVisitor, sink_info: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        构建从入口点到汇聚点的控制流调用栈

        Args:
            visitor: 访问器实例
            sink_info: 汇聚点信息

        Returns:
            控制流调用链
        """
        sink_line = sink_info.get("line", 0)
        sink_name = sink_info.get("name", "Unknown Sink")

        if self.debug:
            print(
                f"[DEBUG] Building control flow chain for sink {sink_name} at line {sink_line}"
            )

        # 找到包含汇聚点的函数
        sink_func = self.tracker.utils.find_function_containing_line(visitor, sink_line)
        if not sink_func:
            if self.debug:
                print(
                    f"[DEBUG] Could not find function containing sink at line {sink_line}"
                )
            return []

        # 获取汇聚点语句信息
        sink_stmt_info = self.tracker.utils.get_statement_at_line(
            visitor, sink_line, context_lines=1
        )

        # 向上追溯调用栈
        call_stack = self.trace_call_stack_to_entry(visitor, sink_func)

        # 转换为调用链格式
        return self.convert_call_stack_to_chain(
            call_stack, sink_info, visitor, sink_func, sink_stmt_info
        )

    def trace_call_stack_to_entry(
        self, visitor: EnhancedTaintAnalysisVisitor, sink_func
    ) -> List[Any]:
        """
        追溯从入口点到目标函数的调用栈

        Args:
            visitor: 访问器实例
            sink_func: 目标函数节点

        Returns:
            调用栈（函数节点列表）
        """
        if not sink_func:
            return []

        # 构建反向调用图
        reverse_call_graph = {}
        for func_name, func_node in visitor.functions.items():
            reverse_call_graph[func_name] = []

        for func_name, func_node in visitor.functions.items():
            for callee in func_node.callees:
                if callee.name not in reverse_call_graph:
                    reverse_call_graph[callee.name] = []
                reverse_call_graph[callee.name].append(func_node)

        # 从配置获取入口点模式
        entry_point_patterns = []
        config = self.tracker.config
        if isinstance(config, dict) and "control_flow" in config:
            control_flow_config = config["control_flow"]
            # 从entry_points配置获取模式
            if "entry_points" in control_flow_config and isinstance(
                control_flow_config["entry_points"], list
            ):
                for entry_config in control_flow_config["entry_points"]:
                    if "patterns" in entry_config and isinstance(
                        entry_config["patterns"], list
                    ):
                        entry_point_patterns.extend(entry_config["patterns"])

            # 也从key_method_names.entry_methods获取入口方法
            if "key_method_names" in control_flow_config and isinstance(
                control_flow_config["key_method_names"], dict
            ):
                key_method_config = control_flow_config["key_method_names"]
                if "entry_methods" in key_method_config and isinstance(
                    key_method_config["entry_methods"], list
                ):
                    # 将entry_methods作为精确匹配模式添加到入口点模式中
                    entry_point_patterns.extend(key_method_config["entry_methods"])

        if self.debug:
            print(
                f"[DEBUG] Got {len(entry_point_patterns)} entry point patterns from config"
            )

        # 优先使用配置中的入口点模式找入口函数
        config_defined_entry_points = []
        if entry_point_patterns:
            for func_name, func_node in visitor.functions.items():
                func_method_name = (
                    func_name.split(".")[-1] if "." in func_name else func_name
                )
                for pattern in entry_point_patterns:
                    # 三种匹配方式：
                    # 1. 精确匹配函数名
                    # 2. 精确匹配方法名部分
                    # 3. 正则匹配（对于包含*的模式）
                    if (
                        pattern == func_name
                        or pattern == func_method_name
                        or (
                            "*" in pattern
                            and re.search(pattern.replace("*", ".*"), func_name)
                        )
                    ):
                        config_defined_entry_points.append(func_node)
                        if self.debug:
                            print(
                                f"[DEBUG] Found config-defined entry point: {func_name} matched pattern {pattern}"
                            )
                        break

        # 如果找到了配置定义的入口点，优先使用它们
        if config_defined_entry_points:
            # 尝试找到从配置定义的入口点到sink函数的路径
            for entry_point in config_defined_entry_points:
                path = self.find_path_to_function(
                    entry_point, sink_func, visitor.functions
                )
                if path:
                    if self.debug:
                        print(
                            f"[DEBUG] Found path from config-defined entry point {entry_point.name} to sink function {sink_func.name}"
                        )
                    return path

        # 如果没有找到配置定义的入口点或没有从配置定义的入口点到sink的路径，使用默认方法
        # 使用BFS查找可能的入口点函数（没有被其他函数调用的函数）
        default_entry_points = []
        for func_name, callers in reverse_call_graph.items():
            if not callers:  # 没有调用者，可能是入口点
                func_node = visitor.functions.get(func_name)
                if func_node:
                    default_entry_points.append(func_node)

        if self.debug:
            print(
                f"[DEBUG] Found {len(default_entry_points)} default entry points: {[ep.name for ep in default_entry_points]}"
            )

        # 对于每个默认入口点，尝试找到到汇聚点函数的路径
        for entry_point in default_entry_points:
            path = self.find_path_to_function(entry_point, sink_func, visitor.functions)
            if path:
                if self.debug:
                    print(
                        f"[DEBUG] Found path from default entry point {entry_point.name} to sink function {sink_func.name}"
                    )
                return path

        # 如果没有找到完整路径，至少返回汇聚点函数
        if self.debug:
            print(f"[DEBUG] No complete path found, returning just the sink function")
        return [sink_func]

    def find_path_to_function(
        self, start_func, target_func, all_functions, max_depth=None
    ):
        """
        使用BFS查找从起始函数到目标函数的路径

        Args:
            start_func: 起始函数
            target_func: 目标函数
            all_functions: 所有函数的字典
            max_depth: 最大搜索深度，如果为None则从配置获取

        Returns:
            函数路径，如果没找到则返回None
        """
        if start_func == target_func:
            return [start_func]

        # 获取配置的最大调用深度
        if max_depth is None:
            max_depth = 20  # 默认值
            config = self.tracker.config
            if isinstance(config, dict) and "control_flow" in config:
                control_flow_config = config["control_flow"]
                if "max_call_depth" in control_flow_config:
                    try:
                        max_depth = int(control_flow_config["max_call_depth"])
                        if self.debug:
                            print(
                                f"[DEBUG] Using config-defined max call depth: {max_depth}"
                            )
                    except (ValueError, TypeError):
                        if self.debug:
                            print(
                                f"[DEBUG] Invalid max_call_depth in config, using default: {max_depth}"
                            )

        queue = [(start_func, [start_func])]
        visited = {start_func.name}
        depth = 0

        while queue and depth < max_depth:
            current, path = queue.pop(0)
            depth += 1

            for callee in current.callees:
                if callee.name == target_func.name:
                    return path + [target_func]

                if callee.name not in visited:
                    visited.add(callee.name)
                    callee_node = all_functions.get(callee.name)
                    if callee_node:
                        queue.append((callee_node, path + [callee_node]))

        if self.debug and depth >= max_depth:
            print(
                f"[DEBUG] Reached max call depth ({max_depth}) when searching path from {start_func.name} to {target_func.name}"
            )

        return None

    def convert_call_stack_to_chain(
        self,
        call_stack: List[Any],
        sink_info: Dict[str, Any],
        visitor: EnhancedTaintAnalysisVisitor,
        sink_func,
        sink_stmt_info: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        将调用栈转换为调用链格式

        Args:
            call_stack: 函数节点列表
            sink_info: 汇聚点信息
            visitor: 访问器实例
            sink_func: 汇聚点函数节点
            sink_stmt_info: 汇聚点语句信息

        Returns:
            调用链（字典列表）
        """
        if not call_stack:
            return []

        call_chain = []
        sink_line = sink_info.get("line", 0)
        sink_name = sink_info.get("name", "Unknown Sink")

        # 全面扫描源文件找出所有的类方法调用关系
        all_method_calls = {}  # 存储方法到其调用者的映射

        if hasattr(visitor, "source_lines") and visitor.source_lines:
            # 1. 先尝试找出所有类定义和方法定义
            class_methods = {}  # 存储类名到其方法列表的映射

            # 通过扫描函数定义来找出类方法
            for func_name, func_node in visitor.functions.items():
                if "." in func_name:
                    parts = func_name.split(".")
                    if len(parts) >= 2:
                        class_name = parts[0]
                        method_name = parts[1]
                        if class_name not in class_methods:
                            class_methods[class_name] = []
                        class_methods[class_name].append(method_name)
                        if self.debug:
                            print(
                                f"[DEBUG] Found class method: {class_name}.{method_name}"
                            )

            # 2. 然后扫描整个源文件查找self.method()调用
            # 从配置文件获取方法调用模式
            method_call_patterns = []
            config = self.tracker.config
            if isinstance(config, dict) and "control_flow" in config:
                control_flow_config = config["control_flow"]
                if "method_call_patterns" in control_flow_config and isinstance(
                    control_flow_config["method_call_patterns"], list
                ):
                    method_call_patterns = control_flow_config["method_call_patterns"]
                    if self.debug:
                        print(
                            f"[DEBUG] Using {len(method_call_patterns)} method call patterns from config"
                        )

            # 如果没有配置方法调用模式，记录日志但不设置默认值
            if not method_call_patterns and self.debug:
                print("[DEBUG] No method call patterns defined in config")

            # 找出所有方法调用
            for line_num, line in enumerate(visitor.source_lines, 1):
                # 找出此行所属的函数节点
                containing_func = None
                for func_name, func_node in visitor.functions.items():
                    if func_node.line_no <= line_num <= func_node.end_line_no:
                        containing_func = func_node
                        break

                if containing_func:
                    # 对每个模式进行匹配
                    for pattern in method_call_patterns:
                        # 根据模式类型进行不同的处理
                        if pattern.startswith("self."):
                            # 匹配self.method()调用
                            matches = re.findall(pattern, line)
                            for called_method in matches:
                                # 检查这个方法在哪个类中定义
                                for class_name, methods in class_methods.items():
                                    if called_method in methods:
                                        # 构建调用信息
                                        caller_method = containing_func.name
                                        callee_method = f"{class_name}.{called_method}"

                                        # 将调用关系存储在all_method_calls中
                                        if callee_method not in all_method_calls:
                                            all_method_calls[callee_method] = []

                                        call_info = {
                                            "caller": caller_method,
                                            "caller_line": line_num,
                                            "statement": line.strip(),
                                            "line": line_num,
                                        }

                                        all_method_calls[callee_method].append(
                                            call_info
                                        )
                                        if self.debug:
                                            print(
                                                f"[DEBUG] Found method call: {caller_method} -> {callee_method} at line {line_num}"
                                            )

                        elif "." in pattern and "(" in pattern:
                            # 匹配class_instance.method()调用
                            instance_method_pattern = pattern
                            matches = re.findall(instance_method_pattern, line)
                            for match in matches:
                                if isinstance(match, tuple) and len(match) >= 2:
                                    instance_name, method_name = match

                                    # 尝试找出实例对应的类
                                    instance_class = None
                                    for class_name in class_methods:
                                        # 这里需要更复杂的逻辑来确定实例的类型
                                        # 简单起见，我们假设实例名可能包含类名
                                        if class_name.lower() in instance_name.lower():
                                            instance_class = class_name
                                            break

                                    if instance_class:
                                        caller_method = containing_func.name
                                        callee_method = (
                                            f"{instance_class}.{method_name}"
                                        )

                                        if callee_method not in all_method_calls:
                                            all_method_calls[callee_method] = []

                                        call_info = {
                                            "caller": caller_method,
                                            "caller_line": line_num,
                                            "statement": line.strip(),
                                            "line": line_num,
                                        }

                                        all_method_calls[callee_method].append(
                                            call_info
                                        )
                                        if self.debug:
                                            print(
                                                f"[DEBUG] Found instance method call: {caller_method} -> {callee_method} at line {line_num}"
                                            )

                # 通用地识别self方法调用
                if "self." in line and "(" in line and method_call_patterns:
                    # 使用配置中的方法调用模式而非硬编码
                    for pattern in method_call_patterns:
                        if "self" in pattern:
                            matches = re.findall(pattern, line)
                            if matches:
                                for match in matches:
                                    # 如果匹配结果是元组，取第一个元素
                                    method_name = (
                                        match[0] if isinstance(match, tuple) else match
                                    )

                                    # 对于每个找到的方法调用，检查它是否是类方法
                                    for class_name, methods in class_methods.items():
                                        if method_name in methods:
                                            # 构建完整的方法调用名
                                            callee_method = (
                                                f"{class_name}.{method_name}"
                                            )

                                            if callee_method not in all_method_calls:
                                                all_method_calls[callee_method] = []

                                            # 记录调用信息
                                            call_info = {
                                                "caller": containing_func.name
                                                if containing_func
                                                else "unknown",
                                                "caller_line": line_num,
                                                "statement": line.strip(),
                                                "line": line_num,
                                                "is_self_method_call": True,
                                            }

                                            all_method_calls[callee_method].append(
                                                call_info
                                            )
                                            if self.debug:
                                                print(
                                                    f"[DEBUG] Recorded self method call: {containing_func.name if containing_func else 'unknown'} -> {callee_method} at line {line_num}"
                                                )

        # 通用地分析任何方法调用
        # 查找sink所在的函数是否被其他方法调用
        if sink_func:
            sink_func_name = sink_func.name
            if sink_func_name in all_method_calls:
                caller_infos = all_method_calls[sink_func_name]
                if self.debug:
                    print(
                        f"[DEBUG] Found {len(caller_infos)} callers for sink function {sink_func_name}"
                    )

        # 添加入口点节点
        if len(call_stack) > 0:
            entry_func = call_stack[0]
            entry_stmt = ""
            if (
                hasattr(visitor, "source_lines")
                and visitor.source_lines
                and entry_func.line_no > 0
                and entry_func.line_no <= len(visitor.source_lines)
            ):
                entry_stmt = visitor.source_lines[entry_func.line_no - 1].strip()

            entry_node = {
                "function": entry_func.name,
                "file": entry_func.file_path,
                "line": entry_func.line_no,
                "statement": entry_stmt
                if entry_stmt
                else f"function {entry_func.name}()",
                "context_lines": [entry_func.line_no, entry_func.end_line_no],
                "type": "entry_point",
                "description": f"Entry point function that initiates the call chain",
            }
            call_chain.append(entry_node)

        # 添加直接调用关系节点
        # 这是一种自顶向下的方法，从调用链的顶部开始追踪
        prev_func_name = ""
        for i, func in enumerate(call_stack):
            current_func_name = func.name

            # 获取当前函数的方法名部分
            method_name = (
                current_func_name.split(".")[-1]
                if "." in current_func_name
                else current_func_name
            )

            # 如果是第一个函数，且它是入口方法，查看它调用的所有方法
            if i == 0 and method_name in self.key_method_names["entry_methods"]:
                if self.debug:
                    print(f"[DEBUG] Processing entry method: {current_func_name}")

                # 查找该入口方法调用的所有其他方法
                for callee, caller_infos in all_method_calls.items():
                    for caller_info in caller_infos:
                        if caller_info["caller"] == current_func_name:
                            # 确定被调用方法名
                            callee_method_name = (
                                callee.split(".")[-1] if "." in callee else callee
                            )

                            # 判断是否是重要方法，如果是，添加标记
                            is_important = (
                                callee_method_name
                                in self.key_method_names["important_methods"]
                            )
                            importance_flag = " [IMPORTANT]" if is_important else ""

                            # 记录所有方法调用
                            method_call_node = {
                                "function": f"{current_func_name} -> {callee}",
                                "file": visitor.file_path,
                                "line": caller_info["line"],
                                "statement": caller_info["statement"],
                                "context_lines": [
                                    caller_info["line"] - 1,
                                    caller_info["line"] + 1,
                                ],
                                "type": "class_method_call",
                                "is_important_method": is_important,
                                "description": f"Class method call from {current_func_name} to {callee}{importance_flag}",
                            }

                            # 如果是重要方法，优先添加到调用链顶部
                            if is_important:
                                call_chain.insert(
                                    0 if len(call_chain) == 0 else 1, method_call_node
                                )
                                if self.debug:
                                    print(
                                        f"[DEBUG] Added IMPORTANT method call: {current_func_name} -> {callee}"
                                    )
                            else:
                                call_chain.append(method_call_node)
                                if self.debug:
                                    print(
                                        f"[DEBUG] Added method call: {current_func_name} -> {callee}"
                                    )

            prev_func_name = current_func_name

        # 检查sink函数是否有调用者
        if sink_func:
            sink_func_name = sink_func.name

            # 添加对sink函数的直接调用
            if sink_func_name in all_method_calls:
                for caller_info in all_method_calls[sink_func_name]:
                    # 获取调用者的方法名部分
                    caller_method_name = (
                        caller_info["caller"].split(".")[-1]
                        if "." in caller_info["caller"]
                        else caller_info["caller"]
                    )

                    # 判断调用者是否是入口方法或重要方法
                    is_entry_method = (
                        caller_method_name in self.key_method_names["entry_methods"]
                    )
                    is_important_method = (
                        caller_method_name in self.key_method_names["important_methods"]
                    )

                    # 如果是入口方法或重要方法，添加到调用链
                    if is_entry_method or is_important_method:
                        caller_line = caller_info["line"]
                        call_stmt = caller_info["statement"]

                        # 添加重要标记
                        importance_flag = ""
                        if is_entry_method:
                            importance_flag = " [ENTRY]"
                        if is_important_method:
                            importance_flag = " [IMPORTANT]"

                        # 添加从入口方法或重要方法到sink函数的调用关系
                        method_call_node = {
                            "function": f"{caller_info['caller']} -> {sink_func_name}",
                            "file": visitor.file_path,
                            "line": caller_line,
                            "statement": call_stmt,
                            "context_lines": [caller_line - 1, caller_line + 1],
                            "type": "class_method_call",
                            "is_entry_method": is_entry_method,
                            "is_important_method": is_important_method,
                            "description": f"Class method call from {caller_info['caller']} to {sink_func_name}{importance_flag}",
                        }

                        # 检查是否已有类似节点
                        has_similar_node = False
                        for node in call_chain:
                            if node.get(
                                "type"
                            ) == "class_method_call" and sink_func_name in node.get(
                                "function", ""
                            ):
                                has_similar_node = True
                                break

                        if not has_similar_node:
                            # 如果是重要方法调用，优先添加到调用链前部
                            if is_important_method:
                                call_chain.insert(
                                    0 if len(call_chain) == 0 else 1, method_call_node
                                )
                            else:
                                call_chain.append(method_call_node)

                            if self.debug:
                                print(
                                    f"[DEBUG] Added direct call to sink function: {caller_info['caller']} -> {sink_func_name}{importance_flag}"
                                )

        # 添加中间函数调用
        for i in range(1, len(call_stack) - 1):
            func = call_stack[i]
            prev_func = call_stack[i - 1]
            call_stmt = ""
            call_line = func.line_no

            # 尝试找到调用语句
            for callee in prev_func.callees:
                if callee.name == func.name and hasattr(callee, "call_line"):
                    call_line = callee.call_line
                    call_stmt = self.tracker.utils.get_statement_at_line(
                        visitor, call_line
                    )["statement"]
                    break

            # 如果找不到调用语句，检查是否是类内部方法调用
            if not call_stmt and func.name in all_method_calls:
                for caller_info in all_method_calls[func.name]:
                    if caller_info["caller"] == prev_func.name:
                        call_stmt = caller_info["statement"]
                        call_line = caller_info["line"]
                        break

            func_node = {
                "function": func.name,
                "file": func.file_path,
                "line": call_line,
                "statement": call_stmt if call_stmt else f"function {func.name}()",
                "context_lines": [func.line_no, func.end_line_no],
                "type": "control_flow",
                "description": f"Function in the call chain leading to the sink",
            }
            call_chain.append(func_node)

        # 如果调用栈中包含汇聚点函数，添加汇聚点容器节点
        if len(call_stack) > 0 and call_stack[-1].name == sink_func.name:
            func = call_stack[-1]
            file_path = getattr(func, "file_path", visitor.file_path)
            func_def_start = func.line_no
            func_def_end = getattr(func, "end_line_no", func_def_start + 1)
            func_def_stmt = ""
            if (
                hasattr(visitor, "source_lines")
                and visitor.source_lines
                and func_def_start > 0
                and func_def_start <= len(visitor.source_lines)
            ):
                func_def_stmt = visitor.source_lines[func_def_start - 1].strip()

            sink_container = {
                "function": func.name,
                "file": file_path,
                "line": func.line_no,
                "statement": func_def_stmt
                if func_def_stmt
                else f"function {func.name}",
                "context_lines": [func_def_start, func_def_end],
                "type": "sink_container",
                "description": f"Function containing sink {sink_name}, at line {sink_line}",
            }
            call_chain.append(sink_container)

        return call_chain
