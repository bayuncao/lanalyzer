#!/usr/bin/env python3
"""
简单测试脚本，用于验证重构是否成功。
测试导入新的类和向后兼容性。
"""

import sys
import os

# 将项目根目录添加到Python路径中
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# 导入重构后的类和向后兼容的类
from lanalyzer.analysis.enhanced import (
    EnhancedTaintAnalysisVisitor,
    EnhancedTaintVisitor,
)

# 测试：确认EnhancedTaintVisitor是EnhancedTaintAnalysisVisitor的别名
def test_backward_compatibility():
    print("测试向后兼容性...", end="")
    assert EnhancedTaintVisitor == EnhancedTaintAnalysisVisitor
    print("成功！")

# 测试：实例化新的访问者类
def test_instantiation():
    print("测试新类实例化...", end="")
    visitor = EnhancedTaintAnalysisVisitor(debug=True, file_path="test.py")
    assert hasattr(visitor, "callgraph")
    assert hasattr(visitor, "datastructures")
    assert hasattr(visitor, "defuse")
    assert hasattr(visitor, "pathsensitive")
    print("成功！")

# 检查文件是否存在
def check_files():
    print("检查文件分拆结果...")
    expected_files = [
        "lanalyzer/analysis/enhanced/visitor_base.py",
        "lanalyzer/analysis/enhanced/visitor_function.py", 
        "lanalyzer/analysis/enhanced/visitor_datastructure.py",
        "lanalyzer/analysis/enhanced/visitor_control.py",
        "lanalyzer/analysis/enhanced/visitor.py",
    ]
    
    for file in expected_files:
        print(f"  检查 {file}...", end="")
        assert os.path.exists(file), f"文件不存在: {file}"
        print("存在")
    
    print("所有文件检查成功！")

if __name__ == "__main__":
    print("开始验证重构结果...")
    check_files()
    test_backward_compatibility()
    test_instantiation()
    print("所有测试通过！重构成功。") 