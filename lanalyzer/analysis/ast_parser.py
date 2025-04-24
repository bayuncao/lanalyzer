import ast
import re
import os
from typing import Any, Dict, Optional, Tuple


class ParentNodeVisitor(ast.NodeVisitor):
    """
    AST visitor that adds parent references to nodes.
    """

    def __init__(self):
        self.parent_map = {}

    def visit(self, node):
        for child in ast.iter_child_nodes(node):
            self.parent_map[child] = node
        super().visit(node)


class TaintVisitor(ast.NodeVisitor):
    def __init__(self, parent_map=None, debug: bool = False, verbose: bool = False, file_path: Optional[str] = None):
        """
        Initialize the taint visitor.

        Args:
            parent_map: Dictionary mapping AST nodes to their parents
            debug: Whether to enable debug output
            verbose: Whether to enable verbose output
            file_path: Path to the file being analyzed
        """
        self.parent_map = parent_map or {}
        self.found_sources = []
        self.found_sinks = []
        self.found_vulnerabilities = []
        self.tainted = {}  # Track which variables are tainted
        self.debug = debug
        self.verbose = verbose
        self.file_path = file_path
        self.source_lines = None  # 存储源代码行
        
        # 如果提供了文件路径，尝试加载源代码
        if file_path and os.path.exists(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.source_lines = f.readlines()
                if self.debug:
                    print(f"加载了 {len(self.source_lines)} 行源代码从 {file_path}")
            except Exception as e:
                if self.debug:
                    print(f"无法加载源代码: {str(e)}")
        
        self.import_aliases = {}  # Track import aliases, e.g., 'import module as alias'
        self.from_imports = {}  # Track from imports, e.g., 'from module import func'
        self.direct_imports = set()  # Track direct imports

    def visit_Import(self, node: ast.Import) -> None:
        """
        Visit an import node to track aliases.
        """
        for name in node.names:
            if self.debug:
                print(f"\n[导入跟踪] 处理导入: {name.name}" + (f" as {name.asname}" if name.asname else ""))
            
            if name.asname:
                self.import_aliases[name.asname] = name.name
                if self.debug:
                    print(f"  记录别名: {name.asname} -> {name.name}")
            else:
                self.direct_imports.add(name.name)
                # 同时添加模块名到 from_imports，以便后续查找
                self.from_imports[name.name] = name.name
                if self.debug:
                    print(f"  记录直接导入: {name.name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """
        Visit a from-import node to track imported names.
        """
        if node.module:
            for name in node.names:
                imported_name = name.name
                full_name = f"{node.module}.{imported_name}"
                if name.asname:
                    self.from_imports[name.asname] = full_name
                    if self.debug:
                        print(
                            f"Tracked from-import with alias: {name.asname} -> {full_name}"
                        )
                else:
                    self.from_imports[imported_name] = full_name
                    if self.debug:
                        print(f"Tracked from-import: {imported_name} -> {full_name}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """
        Visit a function call node in the AST.

        Args:
            node: AST node representing a function call
        """
        # Get the full function name, considering imports and aliases
        func_name, full_name = self._get_func_name_with_module(node.func)
        self.full_func_name = full_name

        line_no = getattr(node, "lineno", 0)
        col_offset = getattr(node, "col_offset", 0)

        if self.debug:
            print(f"Visiting call: {func_name} (full: {full_name}) at line {line_no}")
            args_str = ", ".join([ast.dump(arg) for arg in node.args])
            if args_str:
                print(f"  Args: {args_str}")
            if node.keywords:
                keywords_str = ", ".join(
                    [f"{kw.arg}={ast.dump(kw.value)}" for kw in node.keywords]
                )
                print(f"  Keywords: {keywords_str}")

        # Check if this call is a source
        if func_name and self._is_source(func_name, full_name):
            source_type = self._get_source_type(func_name, full_name)

            source_info = {
                "name": source_type,
                "line": line_no,
                "col": col_offset,
                "node": node,
            }

            self.found_sources.append(source_info)

            if self.debug:
                print(f"Found source: {source_type} at line {line_no}")

            # Track taint if this is part of an assignment
            self._track_assignment_taint(node, source_info)

        # Check if this call is a sink
        if func_name and self._is_sink(func_name, full_name):
            sink_type = self._get_sink_type(func_name, full_name)
            vulnerability_type = self._get_sink_vulnerability_type(sink_type)
            
            sink_info = {
                "name": sink_type,
                "line": line_no,
                "col": col_offset,
                "node": node,
                "vulnerability_type": vulnerability_type,
            }
            
            self.found_sinks.append(sink_info)
            self._check_sink_args(node, sink_type, sink_info)

        # Special handling for eval, exec, execfile
        if func_name in ["eval", "exec", "execfile"]:
            if node.args:
                arg = node.args[0]
                arg_name = None

                # Get the name of the argument
                if isinstance(arg, ast.Name):
                    arg_name = arg.id
                elif isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute):
                    # Handle method calls like data.encode()
                    if isinstance(arg.func.value, ast.Name):
                        arg_name = f"{arg.func.value.id}.{arg.func.attr}()"

                if arg_name and arg_name in self.tainted:
                    source_info = self.tainted[arg_name]

                    # Create a sink info if not already created
                    sink_info = None
                    for sink in self.found_sinks:
                        if sink["line"] == line_no and sink["name"] == "CodeExecution":
                            sink_info = sink
                            break

                    if not sink_info:
                        sink_info = {
                            "name": "CodeExecution",
                            "line": line_no,
                            "col": col_offset,
                            "tainted_args": [],
                        }
                        self.found_sinks.append(sink_info)
                    else:
                        # Make sure tainted_args exists
                        if "tainted_args" not in sink_info:
                            sink_info["tainted_args"] = []

                    # Add the tainted argument to the sink
                    sink_info["tainted_args"].append((arg_name, source_info))

                    if self.debug:
                        print(
                            f"Found tainted argument {arg_name} from {source_info['name']} in {func_name} call"
                        )

        # Continue visiting children
        self.generic_visit(node)

    def _print_function_args(self, node: ast.Call) -> None:
        """
        Print the function arguments for debugging.

        Args:
            node: AST node representing a function call
        """
        args = []
        for arg in node.args:
            if isinstance(arg, ast.Name):
                args.append(f"Name({arg.id})")
            elif isinstance(arg, ast.Constant):
                args.append(f"Constant({repr(arg.value)})")
            elif isinstance(arg, ast.Call):
                func_name, _ = self._get_func_name_with_module(arg.func)
                args.append(f"Call({func_name})")
            else:
                args.append(f"{type(arg).__name__}")

        kws = []
        for kw in node.keywords:
            if isinstance(kw.value, ast.Name):
                kws.append(f"{kw.arg}=Name({kw.value.id})")
            elif isinstance(kw.value, ast.Constant):
                kws.append(f"{kw.arg}=Constant({repr(kw.value.value)})")
            else:
                kws.append(f"{kw.arg}={type(kw.value).__name__}")

        print(f"  Args: {', '.join(args)}")
        if kws:
            print(f"  Keywords: {', '.join(kws)}")

    def visit_Assign(self, node):
        """Visit an assignment node and track taint propagation.

        Args:
            node: AST node representing an assignment
        """
        # Check if the right-hand side is a function call that might be a source
        if isinstance(node.value, ast.Call):
            func_name, full_name = self._get_func_name_with_module(node.value.func)

            if self.debug:
                print(
                    f"Checking assignment with function call: {func_name} (full: {full_name}) at line {getattr(node, 'lineno', 0)}"
                )

            if func_name and self._is_source(func_name, full_name):
                source_type = self._get_source_type(func_name, full_name)
                line_no = getattr(node.value, "lineno", 0)
                col_offset = getattr(node.value, "col_offset", 0)

                source_info = {
                    "name": source_type,
                    "line": line_no,
                    "col": col_offset,
                    "node": node.value,
                }

                self.found_sources.append(source_info)

                if self.debug:
                    print(
                        f"Found source in assignment: {source_type} at line {line_no}"
                    )

                # Track taint for the variables being assigned
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted[target.id] = source_info
                        if self.debug:
                            print(
                                f"Tainted variable '{target.id}' from source {source_type}"
                            )

            # Special handling for input() function which is a common source
            elif func_name == "input":
                line_no = getattr(node.value, "lineno", 0)
                col_offset = getattr(node.value, "col_offset", 0)

                source_info = {
                    "name": "UserInput",
                    "line": line_no,
                    "col": col_offset,
                    "node": node.value,
                }

                self.found_sources.append(source_info)

                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted[target.id] = source_info
                        if self.debug:
                            print(
                                f"Tainted variable '{target.id}' from UserInput at line {line_no}"
                            )

            # Special handling for os.getenv() which is a source for environment variables
            elif func_name == "getenv" and full_name == "os.getenv":
                line_no = getattr(node.value, "lineno", 0)
                col_offset = getattr(node.value, "col_offset", 0)

                source_info = {
                    "name": "EnvironmentVariables",
                    "line": line_no,
                    "col": col_offset,
                    "node": node.value,
                }

                self.found_sources.append(source_info)

                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted[target.id] = source_info
                        if self.debug:
                            print(
                                f"Tainted variable '{target.id}' from EnvironmentVariables at line {line_no}"
                            )

            # Special handling for file read operations
            elif func_name == "read" and isinstance(node.value.func, ast.Attribute):
                line_no = getattr(node.value, "lineno", 0)
                col_offset = getattr(node.value, "col_offset", 0)

                source_info = {
                    "name": "FileRead",
                    "line": line_no,
                    "col": col_offset,
                    "node": node.value,
                }

                self.found_sources.append(source_info)

                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted[target.id] = source_info
                        if self.debug:
                            print(
                                f"Tainted variable '{target.id}' from FileRead at line {line_no}"
                            )

        # Track taint propagation through assignments
        elif isinstance(node.value, ast.Name) and node.value.id in self.tainted:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted[target.id] = self.tainted[node.value.id]
                    if self.debug:
                        print(
                            f"Propagated taint from {node.value.id} to {target.id} at line {getattr(node, 'lineno', 0)}"
                        )

        # Track taint propagation through attribute access
        elif isinstance(node.value, ast.Attribute) and isinstance(
            node.value.value, ast.Name
        ):
            if node.value.value.id in self.tainted:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted[target.id] = self.tainted[node.value.value.id]
                        if self.debug:
                            print(
                                f"Propagated taint from {node.value.value.id}.{node.value.attr} to {target.id} at line {getattr(node, 'lineno', 0)}"
                            )

        # Track taint propagation through subscript
        elif isinstance(node.value, ast.Subscript) and isinstance(
            node.value.value, ast.Name
        ):
            if node.value.value.id in self.tainted:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted[target.id] = self.tainted[node.value.value.id]
                        if self.debug:
                            print(
                                f"Propagated taint from {node.value.value.id}[...] to {target.id} at line {getattr(node, 'lineno', 0)}"
                            )

        # Special handling for sys.argv which is a source for command line arguments
        elif (
            isinstance(node.value, ast.Subscript)
            and isinstance(node.value.value, ast.Attribute)
            and node.value.value.attr == "argv"
            and isinstance(node.value.value.value, ast.Name)
            and node.value.value.value.id == "sys"
        ):
            line_no = getattr(node.value, "lineno", 0)
            col_offset = getattr(node.value, "col_offset", 0)

            source_info = {
                "name": "CommandLineArgs",
                "line": line_no,
                "col": col_offset,
                "node": node.value,
            }

            self.found_sources.append(source_info)

            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted[target.id] = source_info
                    if self.debug:
                        print(
                            f"Tainted variable '{target.id}' from CommandLineArgs at line {line_no}"
                        )

        self.generic_visit(node)

    def _get_func_name_with_module(
        self, func: ast.expr
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Get the name of a function from its AST node, considering imports and aliases.

        Args:
            func: AST node representing a function

        Returns:
            Tuple of (simple function name, full function name with module) or (None, None)
        """
        if self.debug:
            print(f"\n[函数名称解析] 开始解析: {ast.dump(func)}")
        
        if isinstance(func, ast.Name):
            simple_name = func.id
            
            # Check if this is an imported name
            if simple_name in self.from_imports:
                full_name = self.from_imports[simple_name]
                if self.debug:
                    print(f"  从 from_imports 找到映射: {simple_name} -> {full_name}")
                return simple_name, full_name

            # Check if this is an alias
            if simple_name in self.import_aliases:
                module_name = self.import_aliases[simple_name]
                if self.debug:
                    print(f"  从 import_aliases 找到映射: {simple_name} -> {module_name}")
                return simple_name, module_name

            # Check if this is a direct import
            if simple_name in self.direct_imports:
                if self.debug:
                    print(f"  在 direct_imports 中找到: {simple_name}")
                return simple_name, simple_name

            if self.debug:
                print(f"  使用简单名称: {simple_name}")
            return simple_name, simple_name

        elif isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                module_name = func.value.id
                attr_name = func.attr
                
                # Check if the module is an alias
                if module_name in self.import_aliases:
                    real_module = self.import_aliases[module_name]
                    full_name = f"{real_module}.{attr_name}"
                    if self.debug:
                        print(f"  从模块别名解析: {module_name}.{attr_name} -> {full_name}")
                else:
                    full_name = f"{module_name}.{attr_name}"
                    if self.debug:
                        print(f"  构建完整名称: {full_name}")
                
                return attr_name, full_name

            # Handle nested attributes like module.submodule.function
            elif isinstance(func.value, ast.Attribute):
                _, parent_full = self._get_func_name_with_module(func.value)
                if parent_full:
                    full_name = f"{parent_full}.{func.attr}"
                    if self.debug:
                        print(f"  处理嵌套属性: {full_name}")
                    return func.attr, full_name

        if self.debug:
            print("  无法解析函数名称")
        return None, None

    def _is_source(self, func_name: str, full_name: Optional[str] = None) -> bool:
        """
        Check if a function name is a source.

        Args:
            func_name: Simple name of the function
            full_name: Full name of the function with module

        Returns:
            True if the function is a source, False otherwise
        """
        for source in self.sources:
            for pattern in source["patterns"]:
                # Check if pattern matches simple name
                if pattern == func_name:
                    return True

                # Check if pattern matches full name
                if full_name and pattern in full_name:
                    return True

                # Check for wildcard patterns
                if "*" in pattern:
                    regex_pattern = pattern.replace(".", "\\.").replace("*", ".*")
                    if re.match(regex_pattern, func_name) or (
                        full_name and re.match(regex_pattern, full_name)
                    ):
                        return True

        return False

    def _get_source_type(self, func_name: str, full_name: Optional[str] = None) -> str:
        """
        Get the type of a source function.

        Args:
            func_name: Simple name of the function
            full_name: Full name of the function with module

        Returns:
            Type of the source
        """
        for source in self.sources:
            for pattern in source["patterns"]:
                if pattern == func_name or (full_name and pattern in full_name):
                    return source["name"]

                # Check for wildcard patterns
                if "*" in pattern:
                    regex_pattern = pattern.replace(".", "\\.").replace("*", ".*")
                    if re.match(regex_pattern, func_name) or (
                        full_name and re.match(regex_pattern, full_name)
                    ):
                        return source["name"]

        return "Unknown"

    def _is_sink(self, func_name: str, full_name: Optional[str] = None) -> bool:
        """
        Check if a function name is a sink based on configuration patterns.
        """
        if self.debug:
            print(f"\n[Sink检查] 检查函数: {func_name} (完整名称: {full_name or 'N/A'})")
            print(f"  当前导入信息:")
            print(f"    - 直接导入: {self.direct_imports}")
            print(f"    - 别名导入: {self.import_aliases}")
            print(f"    - From导入: {self.from_imports}")
        
        for sink in self.sinks:
            sink_name = sink.get("name", "Unknown")
            if self.debug:
                print(f"  [Sink类型] 检查 {sink_name} 的模式:")
            
            for pattern in sink["patterns"]:
                if self.debug:
                    print(f"    - 当前模式: {pattern}")
                    print(f"      对比: 函数名='{func_name}', 完整名称='{full_name}'")
                
                # 检查简单名称匹配
                if pattern == func_name:
                    if self.debug:
                        print(f"    ✓ 匹配成功: 简单名称匹配 - {pattern}")
                    return True

                # 检查完整名称匹配
                if full_name:
                    # 检查完整匹配
                    if pattern == full_name:
                        if self.debug:
                            print(f"    ✓ 匹配成功: 完整名称精确匹配 - {pattern}")
                        return True
                    # 检查部分匹配
                    if pattern in full_name:
                        if self.debug:
                            print(f"    ✓ 匹配成功: 完整名称包含匹配 - {pattern} in {full_name}")
                        return True

                # 检查通配符模式
                if "*" in pattern:
                    regex_pattern = pattern.replace(".", "\\.").replace("*", ".*")
                    if re.match(regex_pattern, func_name):
                        if self.debug:
                            print(f"    ✓ 匹配成功: 函数名通配符匹配 - {pattern}")
                        return True
                    if full_name and re.match(regex_pattern, full_name):
                        if self.debug:
                            print(f"    ✓ 匹配成功: 完整名称通配符匹配 - {pattern}")
                        return True
                
                if self.debug:
                    print(f"    × 未匹配此模式")

        if self.debug:
            print(f"[Sink检查结果] {func_name}: 不是sink\n")
        return False

    def _get_sink_type(self, func_name: str, full_name: Optional[str] = None) -> str:
        """
        Get the type of a sink function based on configuration.

        Args:
            func_name: Simple name of the function
            full_name: Full name of the function with module

        Returns:
            Type of the sink
        """
        for sink in self.sinks:
            for pattern in sink["patterns"]:
                if pattern == func_name or (full_name and pattern in full_name):
                    return sink["name"]

                if "*" in pattern:
                    regex_pattern = pattern.replace(".", "\\.").replace("*", ".*")
                    if re.match(regex_pattern, func_name) or (
                        full_name and re.match(regex_pattern, full_name)
                    ):
                        return sink["name"]

        return "Unknown"

    def _track_assignment_taint(
        self, node: ast.Call, source_info: Dict[str, Any]
    ) -> None:
        """
        Track taint for variables assigned from sources.

        Args:
            node: AST node representing a function call
            source_info: Information about the source
        """
        # Check if the call is part of an assignment
        if hasattr(node, "parent"):
            parent = node.parent

            # Direct assignment: x = source()
            if isinstance(parent, ast.Assign):
                for target in parent.targets:
                    if isinstance(target, ast.Name):
                        self.tainted[target.id] = source_info
                        if self.debug:
                            print(
                                f"Tainted variable '{target.id}' from direct assignment at line {getattr(parent, 'lineno', 0)}"
                            )

            # Augmented assignment: x += source()
            elif isinstance(parent, ast.AugAssign) and isinstance(
                parent.target, ast.Name
            ):
                self.tainted[parent.target.id] = source_info
                if self.debug:
                    print(
                        f"Tainted variable '{parent.target.id}' from augmented assignment at line {getattr(parent, 'lineno', 0)}"
                    )

            # For loop: for x in source()
            elif isinstance(parent, ast.For) and node == parent.iter:
                if isinstance(parent.target, ast.Name):
                    self.tainted[parent.target.id] = source_info
                    if self.debug:
                        print(
                            f"Tainted variable '{parent.target.id}' from for loop at line {getattr(parent, 'lineno', 0)}"
                        )
                elif isinstance(parent.target, ast.Tuple):
                    for elt in parent.target.elts:
                        if isinstance(elt, ast.Name):
                            self.tainted[elt.id] = source_info
                            if self.debug:
                                print(
                                    f"Tainted variable '{elt.id}' from for loop tuple unpacking at line {getattr(parent, 'lineno', 0)}"
                                )

    def _check_sink_args(
        self, node: ast.Call, sink_type: str, sink_info: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Check if any arguments to a sink function are tainted.

        Args:
            node: AST node representing a function call
            sink_type: Type of the sink
            sink_info: Information about the sink (optional)
        """
        tainted_args = []

        # 检查是否为 open() 调用，跟踪文件句柄和路径之间的关系
        func_name, full_name = self._get_func_name_with_module(node.func)
        if func_name == "open" and len(node.args) >= 1:
            # 找到 open() 所在的赋值表达式
            if (
                hasattr(node, "parent")
                and isinstance(node.parent, ast.Assign)
                and len(node.parent.targets) == 1
            ):
                if isinstance(node.parent.targets[0], ast.Name):
                    file_handle_name = node.parent.targets[0].id

                    # 检查路径参数是否被污染
                    path_arg = node.args[0]
                    if isinstance(path_arg, ast.Name) and path_arg.id in self.tainted:
                        if not hasattr(self, "file_handles"):
                            self.file_handles = {}

                        self.file_handles[file_handle_name] = {
                            "source_var": path_arg.id,
                            "source_info": self.tainted[path_arg.id],
                        }

                        if self.debug:
                            print(
                                f"Tracking file handle '{file_handle_name}' from tainted path '{path_arg.id}'"
                            )

        # Check positional arguments
        for i, arg in enumerate(node.args):
            tainted = False
            source_info = None
            arg_name = None

            # check if the argument is a tainted variable
            if isinstance(arg, ast.Name):
                arg_name = arg.id
                if arg_name in self.tainted:
                    source_info = self.tainted[arg_name]
                    tainted = True
                # check if the argument is a tainted file handle
                elif hasattr(self, "file_handles") and arg_name in self.file_handles:
                    file_info = self.file_handles[arg_name]
                    source_info = file_info["source_info"]
                    tainted = True
                    arg_name = f"{arg_name}(from {file_info['source_var']})"

                    if self.debug:
                        print(f"Found tainted file handle '{arg_name}' passed to sink")

            # check if the argument is a method call (e.g. tainted.encode())
            elif (
                isinstance(arg, ast.Call)
                and isinstance(arg.func, ast.Attribute)
                and isinstance(arg.func.value, ast.Name)
            ):
                base_var = arg.func.value.id
                if base_var in self.tainted:
                    source_info = self.tainted[base_var]
                    tainted = True
                    method_name = arg.func.attr
                    arg_name = f"{base_var}.{method_name}()"

                    if self.debug:
                        print(
                            f"Found tainted method call '{arg_name}' from tainted variable '{base_var}'"
                        )

            # check if the argument is a direct function call
            elif isinstance(arg, ast.Call):
                # check if the function is an open() call
                sub_func_name, sub_full_name = self._get_func_name_with_module(arg.func)
                if sub_func_name == "open":
                    # directly identify as FileRead source
                    source_info = {
                        "name": "FileRead",
                        "line": getattr(arg, "lineno", 0),
                        "col": getattr(arg, "col_offset", 0),
                    }
                    tainted = True
                    arg_name = f"direct_call_{i}"

            # check if the argument is a tainted file handle created in a with statement
            elif (
                isinstance(arg, ast.Name)
                and arg.id in self.file_handles
                and self.file_handles[arg.id].get("from_with")
            ):
                file_info = self.file_handles[arg.id]
                source_info = file_info["source_info"]
                tainted = True
                arg_name = f"{arg.id}(from {file_info['source_var']} in with)"

                if self.debug:
                    print(
                        f"Found tainted file handle '{arg_name}' from with-statement passed to sink"
                    )

            if tainted and source_info:
                tainted_args.append((arg_name, source_info))
                if self.debug:
                    print(
                        f"Found tainted argument '{arg_name}' (position {i}) to sink '{sink_type}' at line {getattr(node, 'lineno', 0)}"
                    )

        # Check keyword arguments
        for i, kw in enumerate(node.keywords):
            tainted = False
            source_info = None
            arg_name = None

            if isinstance(kw.value, ast.Name):
                arg_name = f"{kw.arg}={kw.value.id}"
                if kw.value.id in self.tainted:
                    source_info = self.tainted[kw.value.id]
                    tainted = True
                # check if the argument is a tainted file handle
                elif hasattr(self, "file_handles") and kw.value.id in self.file_handles:
                    file_info = self.file_handles[kw.value.id]
                    source_info = file_info["source_info"]
                    tainted = True
                    arg_name = f"{kw.arg}={kw.value.id}(from {file_info['source_var']})"

            # check if the argument is a method call (e.g. tainted.encode())
            elif (
                isinstance(kw.value, ast.Call)
                and isinstance(kw.value.func, ast.Attribute)
                and isinstance(kw.value.func.value, ast.Name)
            ):
                base_var = kw.value.func.value.id
                if base_var in self.tainted:
                    source_info = self.tainted[base_var]
                    tainted = True
                    method_name = kw.value.func.attr
                    arg_name = f"{kw.arg}={base_var}.{method_name}()"

            elif isinstance(kw.value, ast.Call):
                # Check if the argument is a direct call to a source
                sub_func_name, sub_full_name = self._get_func_name_with_module(
                    kw.value.func
                )
                if sub_func_name and self._is_source(sub_func_name, sub_full_name):
                    source_type = self._get_source_type(sub_func_name, sub_full_name)
                    source_info = {
                        "name": source_type,
                        "line": getattr(kw.value, "lineno", 0),
                        "col": getattr(kw.value, "col_offset", 0),
                    }
                    tainted = True
                    arg_name = f"{kw.arg}=direct_call"

            if tainted and source_info:
                tainted_args.append((arg_name, source_info))
                if self.debug:
                    print(
                        f"Found tainted keyword argument '{arg_name}' to sink '{sink_type}' at line {getattr(node, 'lineno', 0)}"
                    )

        if tainted_args and sink_info is not None:
            sink_info["tainted_args"] = tainted_args
            if self.debug:
                print(
                    f"Added {len(tainted_args)} tainted args to sink info at line {getattr(node, 'lineno', 0)}"
                )

        if not tainted_args and self.debug:
            print(
                f"No tainted arguments found for sink '{sink_type}' at line {getattr(node, 'lineno', 0)}"
            )
            # Print all arguments for debugging
            arg_names = []
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    arg_names.append(arg.id)
            print(f"  Arguments: {', '.join(arg_names) or 'None'}")
            print(f"  Known tainted variables: {list(self.tainted.keys())}")
            if hasattr(self, "file_handles") and self.file_handles:
                print(f"  Known file handles: {list(self.file_handles.keys())}")

    def visit_With(self, node: ast.With) -> None:
        """
        Visit a with statement to track file handles for taint tracking.

        Args:
            node: AST node representing a with statement
        """
        for item in node.items:
            if isinstance(item.context_expr, ast.Call):
                func_name, full_name = self._get_func_name_with_module(
                    item.context_expr.func
                )

                # check if the context_expr is an open() call
                if func_name == "open" and len(item.context_expr.args) >= 1:
                    # check if the path argument is tainted
                    path_arg = item.context_expr.args[0]
                    if (
                        isinstance(item.optional_vars, ast.Name)
                        and isinstance(path_arg, ast.Name)
                        and path_arg.id in self.tainted
                    ):
                        file_handle_name = item.optional_vars.id

                        if not hasattr(self, "file_handles"):
                            self.file_handles = {}

                        self.file_handles[file_handle_name] = {
                            "source_var": path_arg.id,
                            "source_info": self.tainted[path_arg.id],
                        }

                        if self.debug:
                            print(
                                f"Tracking file handle '{file_handle_name}' from tainted path '{path_arg.id}' in with statement"
                            )

        # continue visiting the body of the with statement
        self.generic_visit(node)

    def _get_sink_vulnerability_type(self, sink_type: str) -> str:
        """
        Get the vulnerability type corresponding to the sink type.

        Args:
            sink_type: The type name of the sink

        Returns:
            The vulnerability type name
        """
        # map the sink type to the vulnerability type
        vulnerability_map = {
            "SQLQuery": "SQL Injection",
            "CommandExecution": "Command Injection",
            "FileOperation": "Path Traversal",
            "ResponseData": "Cross-Site Scripting",
            "TemplateOperation": "Template Injection",
            "Deserialization": "Deserialization Attack",
            "XMLOperation": "XXE Injection",
        }

        # if the sink type is in the vulnerability map, return the corresponding vulnerability type
        if sink_type in vulnerability_map:
            return vulnerability_map[sink_type]

        # for custom sinks, check if the vulnerability_type is directly defined in the sinks configuration
        for sink in self.sinks:
            if sink.get("name") == sink_type and "vulnerability_type" in sink:
                return sink["vulnerability_type"]

        # default return the sink type as the vulnerability type
        return f"{sink_type} Vulnerability"
