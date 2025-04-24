"""
调用图模块 - 用于构建和分析Python代码中的函数调用关系图。
"""

import os
import json
from typing import Dict, List, Set, Optional, Any, Tuple
from collections import defaultdict, deque


class CallGraphNode:
    """
    调用图节点，代表程序中的一个函数或方法。
    """
    
    def __init__(self, name: str, file_path: str, line_no: int, 
                 is_method: bool = False, class_name: Optional[str] = None):
        """
        初始化调用图节点。
        
        Args:
            name: 函数或方法名称
            file_path: 函数定义所在的文件路径
            line_no: 函数定义的行号
            is_method: 是否是类的方法
            class_name: 如果是方法，所属的类名
        """
        self.name = name
        self.file_path = file_path
        self.line_no = line_no
        self.is_method = is_method
        self.class_name = class_name
        self.callers = []  # 调用此函数的函数列表
        self.callees = []  # 此函数调用的函数列表
        
    def add_caller(self, caller_node: 'CallGraphNode', line_no: int) -> None:
        """
        添加调用者。
        
        Args:
            caller_node: 调用此函数的函数节点
            line_no: 调用发生的行号
        """
        caller_info = (caller_node, line_no)
        if caller_info not in self.callers:
            self.callers.append(caller_info)
            
    def add_callee(self, callee_node: 'CallGraphNode', line_no: int) -> None:
        """
        添加被调用者。
        
        Args:
            callee_node: 被此函数调用的函数节点
            line_no: 调用发生的行号
        """
        callee_info = (callee_node, line_no)
        if callee_info not in self.callees:
            self.callees.append(callee_info)
            
    def to_dict(self) -> Dict[str, Any]:
        """
        将节点转换为字典表示。
        
        Returns:
            字典形式的节点信息
        """
        return {
            "name": self.name,
            "file_path": self.file_path,
            "line_no": self.line_no,
            "is_method": self.is_method,
            "class_name": self.class_name,
            "callers": [{"name": c[0].name, "line_no": c[1]} for c in self.callers],
            "callees": [{"name": c[0].name, "line_no": c[1]} for c in self.callees],
        }


class CallGraph:
    """
    调用图类，用于构建和分析程序中的函数调用关系。
    """
    
    def __init__(self):
        """初始化一个空的调用图。"""
        self.nodes = {}  # 名称 -> CallGraphNode
        self.file_nodes = defaultdict(list)  # 文件路径 -> 节点列表
        
    def add_node(self, name: str, file_path: str, line_no: int,
                is_method: bool = False, class_name: Optional[str] = None) -> CallGraphNode:
        """
        添加函数节点到调用图。如果节点已存在，则返回现有节点。
        
        Args:
            name: 函数名称
            file_path: 函数定义所在的文件路径
            line_no: 函数定义的行号
            is_method: 是否是类的方法
            class_name: 如果是方法，所属的类名
            
        Returns:
            添加的或已存在的CallGraphNode对象
        """
        if name in self.nodes:
            return self.nodes[name]
            
        node = CallGraphNode(name, file_path, line_no, is_method, class_name)
        self.nodes[name] = node
        self.file_nodes[file_path].append(node)
        return node
        
    def add_call(self, caller: str, callee: str, line_no: int) -> bool:
        """
        添加调用关系。
        
        Args:
            caller: 调用者函数名称
            callee: 被调用函数名称
            line_no: 调用发生的行号
            
        Returns:
            是否成功添加调用关系
        """
        if caller not in self.nodes or callee not in self.nodes:
            return False
            
        caller_node = self.nodes[caller]
        callee_node = self.nodes[callee]
        
        caller_node.add_callee(callee_node, line_no)
        callee_node.add_caller(caller_node, line_no)
        return True
        
    def get_callers(self, function_name: str) -> List[Tuple[CallGraphNode, int]]:
        """
        获取调用指定函数的所有函数。
        
        Args:
            function_name: 目标函数名称
            
        Returns:
            调用此函数的所有函数节点及调用行号
        """
        if function_name not in self.nodes:
            return []
            
        return self.nodes[function_name].callers
        
    def get_callees(self, function_name: str) -> List[Tuple[CallGraphNode, int]]:
        """
        获取指定函数调用的所有函数。
        
        Args:
            function_name: 目标函数名称
            
        Returns:
            被此函数调用的所有函数节点及调用行号
        """
        if function_name not in self.nodes:
            return []
            
        return self.nodes[function_name].callees
        
    def find_call_chains(self, start_function: str, end_function: str, 
                         max_depth: int = 10) -> List[List[str]]:
        """
        查找从起始函数到目标函数的所有调用链。
        
        Args:
            start_function: 起始函数名称
            end_function: 目标函数名称
            max_depth: 最大搜索深度，防止无限循环
            
        Returns:
            所有可能的调用链路径列表，每个路径是函数名称列表
        """
        if start_function not in self.nodes or end_function not in self.nodes:
            return []
            
        # 使用DFS查找所有路径
        paths = []
        visited = set()
        
        def dfs(current: str, path: List[str], depth: int):
            if depth > max_depth:
                return
                
            if current == end_function:
                paths.append(path.copy())
                return
                
            visited.add(current)
            
            for callee, _ in self.nodes[current].callees:
                if callee.name not in visited:
                    path.append(callee.name)
                    dfs(callee.name, path, depth + 1)
                    path.pop()
                    
            visited.remove(current)
            
        dfs(start_function, [start_function], 0)
        return paths
        
    def find_paths_to_sink(self, sink_function: str, max_depth: int = 10) -> Dict[str, List[List[str]]]:
        """
        查找能到达指定汇聚点函数的所有函数及其路径。
        
        Args:
            sink_function: 汇聚点函数名称
            max_depth: 最大搜索深度
            
        Returns:
            以函数名为键，到达汇聚点的路径列表为值的字典
        """
        if sink_function not in self.nodes:
            return {}
            
        # 使用反向DFS，从汇聚点开始向上查找
        result = {}
        
        def find_paths_from_node(node_name: str) -> List[List[str]]:
            if node_name in result:
                return result[node_name]
                
            # 从此节点到汇聚点的所有路径
            paths = []
            
            # 如果当前节点就是汇聚点
            if node_name == sink_function:
                paths.append([node_name])
                result[node_name] = paths
                return paths
                
            # 检查此节点直接调用的函数
            if node_name in self.nodes:
                node = self.nodes[node_name]
                for callee, _ in node.callees:
                    # 递归查找从被调用函数到汇聚点的路径
                    callee_paths = find_paths_from_node(callee.name)
                    
                    # 如果找到路径，添加当前节点
                    for path in callee_paths:
                        if len(path) < max_depth:  # 控制路径长度
                            new_path = [node_name] + path
                            paths.append(new_path)
                            
            result[node_name] = paths
            return paths
            
        # 对每个节点尝试查找到汇聚点的路径
        for node_name in self.nodes:
            find_paths_from_node(node_name)
            
        return result
        
    def to_dict(self) -> Dict[str, Any]:
        """
        将整个调用图转换为字典表示。
        
        Returns:
            字典形式的调用图
        """
        return {
            "nodes": {name: node.to_dict() for name, node in self.nodes.items()},
            "file_nodes": {file_path: [node.name for node in nodes] 
                          for file_path, nodes in self.file_nodes.items()}
        }
        
    def to_dot(self, output_file: Optional[str] = None) -> str:
        """
        将调用图转换为DOT格式，用于使用Graphviz等工具可视化。
        
        Args:
            output_file: 如果提供，将DOT格式内容写入此文件
            
        Returns:
            DOT格式的调用图表示
        """
        dot_lines = ['digraph CallGraph {', 
                    '  node [shape=box, style=filled, color=lightblue];', 
                    '  rankdir=LR;']
                    
        # 添加节点
        for name, node in self.nodes.items():
            label = name
            if node.is_method and node.class_name:
                label = f"{node.class_name}.{name}"
                
            file_name = os.path.basename(node.file_path)
            dot_lines.append(f'  "{name}" [label="{label}\\n{file_name}:{node.line_no}"];')
            
        # 添加边
        for name, node in self.nodes.items():
            for callee, line_no in node.callees:
                dot_lines.append(f'  "{name}" -> "{callee.name}" [label="{line_no}"];')
                
        dot_lines.append('}')
        dot_content = '\n'.join(dot_lines)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(dot_content)
                
        return dot_content
        
    @classmethod
    def from_ast_visitor_data(cls, visitor_data: Dict) -> 'CallGraph':
        """
        从AST访问器数据构建调用图。
        
        Args:
            visitor_data: AST访问器生成的数据
            
        Returns:
            构建的调用图对象
        """
        graph = cls()
        
        # 添加节点
        for node_data in visitor_data.get('nodes', []):
            graph.add_node(
                name=node_data['name'],
                file_path=node_data['file_path'],
                line_no=node_data['line_no'],
                is_method=node_data.get('is_method', False),
                class_name=node_data.get('class_name')
            )
            
        # 添加调用边
        for edge_data in visitor_data.get('edges', []):
            graph.add_call(
                caller=edge_data['caller'],
                callee=edge_data['callee'],
                line_no=edge_data['line_no']
            )
            
        return graph
        
    @classmethod
    def build_from_files(cls, ast_visitor_results: List[Dict]) -> 'CallGraph':
        """
        从多个文件的AST访问器结果构建完整的调用图。
        
        Args:
            ast_visitor_results: 多个AST访问器的结果列表
            
        Returns:
            构建的调用图对象
        """
        graph = cls()
        
        # 合并所有文件的数据
        for result in ast_visitor_results:
            # 从每个文件提取调用图数据
            call_graph_data = result.get('call_graph_data', {})
            
            # 添加节点
            for node_data in call_graph_data.get('nodes', []):
                graph.add_node(
                    name=node_data['name'],
                    file_path=node_data['file_path'],
                    line_no=node_data['line_no'],
                    is_method=node_data.get('is_method', False),
                    class_name=node_data.get('class_name')
                )
                
            # 添加调用边
            for edge_data in call_graph_data.get('edges', []):
                graph.add_call(
                    caller=edge_data['caller'],
                    callee=edge_data['callee'],
                    line_no=edge_data['line_no']
                )
                
        return graph
        
    def save_to_file(self, output_file: str) -> None:
        """
        将调用图保存到JSON文件。
        
        Args:
            output_file: 输出文件路径
        """
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)
            
    @classmethod
    def load_from_file(cls, input_file: str) -> 'CallGraph':
        """
        从JSON文件加载调用图。
        
        Args:
            input_file: 输入文件路径
            
        Returns:
            加载的调用图对象
        """
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        graph = cls()
        
        # 添加节点
        for name, node_data in data.get('nodes', {}).items():
            graph.add_node(
                name=name,
                file_path=node_data['file_path'],
                line_no=node_data['line_no'],
                is_method=node_data.get('is_method', False),
                class_name=node_data.get('class_name')
            )
            
        # 添加调用关系
        for name, node_data in data.get('nodes', {}).items():
            for callee in node_data.get('callees', []):
                callee_name = callee['name']
                if callee_name in graph.nodes:
                    graph.add_call(name, callee_name, callee['line_no'])
                    
        return graph
        
    def find_entry_points(self) -> List[str]:
        """
        查找可能的入口点函数（没有被其他函数调用的函数）。
        
        Returns:
            可能的入口点函数名称列表
        """
        entry_points = []
        for name, node in self.nodes.items():
            if not node.callers:
                entry_points.append(name)
                
        return entry_points
        
    def find_leaf_functions(self) -> List[str]:
        """
        查找叶子函数（不调用其他函数的函数）。
        
        Returns:
            叶子函数名称列表
        """
        leaf_functions = []
        for name, node in self.nodes.items():
            if not node.callees:
                leaf_functions.append(name)
                
        return leaf_functions
        
    def get_function_depth(self, function_name: str) -> int:
        """
        计算函数在调用图中的深度（从入口点到此函数的最短路径长度）。
        
        Args:
            function_name: 函数名称
            
        Returns:
            函数深度，如果无法到达则返回-1
        """
        if function_name not in self.nodes:
            return -1
            
        # 使用BFS寻找最短路径
        entry_points = self.find_entry_points()
        if function_name in entry_points:
            return 0
            
        queue = deque([(entry, 1) for entry in entry_points])
        visited = set(entry_points)
        
        while queue:
            current, depth = queue.popleft()
            
            for callee, _ in self.nodes[current].callees:
                if callee.name == function_name:
                    return depth
                    
                if callee.name not in visited:
                    visited.add(callee.name)
                    queue.append((callee.name, depth + 1))
                    
        return -1 