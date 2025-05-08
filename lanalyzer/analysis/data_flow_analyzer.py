"""
Data flow analysis for taint analysis call chains.
"""

import re
from typing import Any, Dict, List, Set, Optional

from lanalyzer.analysis.visitor import EnhancedTaintAnalysisVisitor


class DataFlowAnalyzer:
    """Analyze data flow between taint sources and sinks."""

    def __init__(self, builder):
        """Initialize with reference to parent builder."""
        self.builder = builder
        self.tracker = builder.tracker
        self.debug = builder.debug

    def find_data_flow_steps(
        self,
        visitor: EnhancedTaintAnalysisVisitor,
        var_name: str,
        source_line: int,
        sink_line: int,
        sink_arg_expressions: List[str],
        data_flow_path: List[Dict[str, Any]],
        added_sources: Set[str],
    ) -> None:
        """
        查找从源变量到sink参数之间的数据流路径，包括变量赋值和转换操作。

        Args:
            visitor: 访问器实例
            var_name: 源变量名
            source_line: 源所在行
            sink_line: 汇聚点所在行
            sink_arg_expressions: sink中的参数表达式
            data_flow_path: 收集数据流路径的列表
            added_sources: 已添加源的集合
        """
        if not hasattr(visitor, "source_lines") or not visitor.source_lines:
            return

        # 构建变量使用映射
        var_usage_map = {}

        # 查找变量的所有使用点
        # 首先收集所有相关的赋值语句
        assignments = []
        for line_num in range(source_line + 1, sink_line):
            if line_num > len(visitor.source_lines):
                break

            line = visitor.source_lines[line_num - 1].strip()
            # 检查变量是否出现在这行中
            if var_name in line:
                # 如果是赋值语句且变量在赋值右侧
                if "=" in line and var_name in line.split("=", 1)[1]:
                    left_side = line.split("=", 1)[0].strip()
                    # 避免处理类似 var_name1 = var_name2 的情况
                    if var_name != left_side and left_side.isidentifier():
                        var_usage_map[left_side] = {
                            "line": line_num,
                            "statement": line,
                            "from_var": var_name,
                        }
                        assignments.append(
                            {
                                "line": line_num,
                                "statement": line,
                                "from_var": var_name,
                                "to_var": left_side,
                            }
                        )

                # 检查数组索引访问
                # 例如 var2 = var_name[1]
                elif "[" in line and "]" in line and "=" in line:
                    left_side = line.split("=", 1)[0].strip()
                    right_side = line.split("=", 1)[1].strip()
                    # 检查var_name是否是数组索引访问的基础
                    array_access_pattern = r"{}(?:\s*\[[^\]]+\])".format(
                        re.escape(var_name)
                    )
                    if re.search(array_access_pattern, right_side):
                        # 提取索引访问的详细信息
                        index_info = self.extract_index_access_info(
                            right_side, var_name
                        )

                        var_usage_map[left_side] = {
                            "line": line_num,
                            "statement": line,
                            "from_var": var_name,
                            "is_array_access": True,
                            "index_info": index_info,
                        }
                        assignments.append(
                            {
                                "line": line_num,
                                "statement": line,
                                "from_var": var_name,
                                "to_var": left_side,
                                "is_array_access": True,
                                "index_info": index_info,
                            }
                        )

        # 对赋值语句按行号排序
        assignments.sort(key=lambda x: x["line"])

        # 只添加到最终sink的数据流路径
        relevant_assignments = []

        # 检查sink参数中使用的变量是否在我们跟踪的数据流中
        for expr in sink_arg_expressions:
            # 检查是否包含索引访问
            if "[" in expr and "]" in expr:
                array_var_match = re.match(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*\[", expr)
                if array_var_match:
                    array_var = array_var_match.group(1)

                    # 提取更多索引访问的细节信息
                    index_info = self.extract_index_access_info(expr, array_var)

                    # 构建数据流图并找出从源变量到sink中使用变量的路径
                    visited = set([var_name])
                    path = self.find_var_path(
                        var_name, array_var, var_usage_map, visited
                    )

                    if path:
                        # 转换路径为数据流步骤
                        for step_var in path[1:]:  # 跳过源变量自身
                            step_info = var_usage_map[step_var]

                            # 增强数据流描述
                            step_desc = (
                                f"Data flow: {step_info['from_var']} → {step_var}"
                            )

                            if step_info.get("is_array_access"):
                                step_index_info = step_info.get("index_info", {})
                                if step_index_info:
                                    index_value = step_index_info.get("index", "?")
                                    step_desc += f" (array element access at index {index_value})"
                                else:
                                    step_desc += " (array element access)"

                            # 如果这是直接流向sink的变量，添加更多上下文
                            if step_var == array_var:
                                if index_info.get("is_index_access"):
                                    index_value = index_info.get("index")
                                    index_type = index_info.get("index_type", "unknown")

                                    if index_type == "integer":
                                        step_desc += f" → Final step: {step_var}[{index_value}] used in sink"
                                    else:
                                        step_desc += f" → Final step: {step_var}[{index_value}] used in sink"

                            flow_step = {
                                "function": f"Data flow: {step_info['statement']}",
                                "file": visitor.file_path,
                                "line": step_info["line"],
                                "statement": step_info["statement"],
                                "context_lines": [
                                    step_info["line"] - 1,
                                    step_info["line"] + 1,
                                ],
                                "type": "data_flow",
                                "description": step_desc,
                            }

                            source_key = f"{step_info['line']}:{step_info['statement']}"
                            if source_key not in added_sources:
                                relevant_assignments.append(flow_step)
                    elif var_name == array_var:
                        # 直接从源变量到sink的情况
                        index_value = index_info.get("index", "?")
                        step_desc = f"Data flow: {var_name}[{index_value}] used directly in sink"

                        # 找到最近的源变量语句作为上下文
                        source_stmt = ""
                        for line_num in range(source_line, sink_line):
                            if line_num > len(visitor.source_lines):
                                break
                            line = visitor.source_lines[line_num - 1].strip()
                            if (
                                var_name in line
                                and "=" in line
                                and line.split("=")[0].strip() == var_name
                            ):
                                source_stmt = line
                                break

                        if source_stmt:
                            flow_step = {
                                "function": f"Data flow: Direct use of source variable",
                                "file": visitor.file_path,
                                "line": source_line,
                                "statement": source_stmt,
                                "context_lines": [source_line - 1, source_line + 1],
                                "type": "data_flow",
                                "description": step_desc,
                            }

                            source_key = f"{source_line}:{source_stmt}"
                            if source_key not in added_sources:
                                relevant_assignments.append(flow_step)

        # 按行号排序并添加到数据流路径
        relevant_assignments.sort(key=lambda x: x["line"])
        for assignment in relevant_assignments:
            data_flow_path.append(assignment)

    def find_var_path(
        self,
        start_var: str,
        target_var: str,
        var_map: Dict[str, Dict[str, Any]],
        visited: Set[str],
    ) -> List[str]:
        """
        使用广度优先搜索找出从起始变量到目标变量的路径

        Args:
            start_var: 起始变量名
            target_var: 目标变量名
            var_map: 变量映射关系
            visited: 已访问的变量集合

        Returns:
            变量名列表，表示从start_var到target_var的路径，如果没有路径则返回空列表
        """
        if start_var == target_var:
            return [start_var]

        queue = [(start_var, [start_var])]

        while queue:
            current_var, path = queue.pop(0)

            # 找出所有从current_var派生的变量
            for var_name, info in var_map.items():
                if info.get("from_var") == current_var and var_name not in visited:
                    new_path = path + [var_name]

                    if var_name == target_var:
                        return new_path

                    visited.add(var_name)
                    queue.append((var_name, new_path))

        return []  # 没找到路径

    def extract_index_access_info(self, expr: str, var_name: str) -> Dict[str, Any]:
        """
        从表达式中提取索引访问信息。
        例如，从 "message[1]" 中提取索引值 "1"，基础变量 "message"。

        Args:
            expr: 包含索引访问的表达式
            var_name: 基础变量名

        Returns:
            包含索引访问信息的字典
        """
        result = {
            "base_var": var_name,
            "full_expr": expr.strip(),
            "index": None,
            "is_index_access": False,
        }

        # 匹配索引访问模式
        index_match = re.search(r"{}\s*\[(.*?)\]".format(re.escape(var_name)), expr)
        if index_match:
            result["is_index_access"] = True
            result["index"] = index_match.group(1).strip()

            # 尝试确定索引的类型（如数字、字符串等）
            index_val = result["index"]
            if index_val.isdigit() or (
                index_val.startswith("-") and index_val[1:].isdigit()
            ):
                result["index_type"] = "integer"
                result["index_value"] = int(index_val)
            elif (index_val.startswith('"') and index_val.endswith('"')) or (
                index_val.startswith("'") and index_val.endswith("'")
            ):
                result["index_type"] = "string"
                result["index_value"] = index_val.strip("'\"")
            else:
                result["index_type"] = "variable"

        return result
