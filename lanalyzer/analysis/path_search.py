"""path_search.py
为调用链分析提供通用路径搜索算法（DFS）。
"""
from typing import List, Optional

__all__ = ["find_shortest_path"]


def _dfs(current_func, target_func, path, depth, max_depth, paths, debug=False):
    if current_func == target_func:
        paths.append(path + [current_func])
        return
    if depth >= max_depth:
        return
    for callee in getattr(current_func, "callees", []):
        if callee in path:
            continue
        _dfs(callee, target_func, path + [current_func], depth + 1, max_depth, paths, debug)


def find_shortest_path(source_func, sink_func, *, max_depth: int = 20, debug: bool = False) -> Optional[List]:
    """寻找最短调用路径，返回函数节点列表或 None。"""
    paths: List[List] = []
    _dfs(source_func, sink_func, [], 0, max_depth, paths, debug)
    if debug:
        print(f"[path_search] 完成，路径数: {len(paths)}")
    if not paths:
        return None
    return min(paths, key=len) 