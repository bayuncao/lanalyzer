"""builder_core.py
核心封装，整合多种路径/调用链构建算法，对外提供统一接口。
"""

# 当前仅包装 `path_search.find_shortest_path`，后续可在此扩展多策略。

from typing import List, Optional

from .path_search import find_shortest_path as _find_shortest_path

__all__ = ["find_shortest_path"]


def find_shortest_path(source_func, sink_func, *, max_depth: int = 20, debug: bool = False) -> Optional[List]:
    """对外统一接口，调用 Path Search 实现。

    该方法目前简单委托给 :pyfunc:`lanalyzer.analysis.path_search.find_shortest_path`，
    后续可增加缓存、启发式剪枝等高级特性。
    """
    return _find_shortest_path(source_func, sink_func, max_depth=max_depth, debug=debug) 