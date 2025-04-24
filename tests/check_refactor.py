#!/usr/bin/env python3
"""
Simple test script to verify successful refactoring.
Tests importing new classes and backward compatibility.
"""

import sys
import os

# Add project root directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import refactored classes and backward compatible class
from lanalyzer.analysis import (
    EnhancedTaintAnalysisVisitor,
    EnhancedTaintVisitor,
)

# Test: Confirm EnhancedTaintVisitor is an alias for EnhancedTaintAnalysisVisitor
def test_backward_compatibility():
    print("Testing backward compatibility...", end="")
    assert EnhancedTaintVisitor == EnhancedTaintAnalysisVisitor
    print("Success!")

# Test: Instantiate the new visitor class
def test_instantiation():
    print("Testing new class instantiation...", end="")
    visitor = EnhancedTaintAnalysisVisitor(debug=True, file_path="test.py")
    assert hasattr(visitor, "callgraph")
    assert hasattr(visitor, "datastructures")
    assert hasattr(visitor, "defuse")
    assert hasattr(visitor, "pathsensitive")
    print("Success!")

# Check if files exist
def check_files():
    print("Checking file splitting results...")
    expected_files = [
        "lanalyzer/analysis/visitor_base.py",
        "lanalyzer/analysis/visitor_function.py", 
        "lanalyzer/analysis/visitor_datastructure.py",
        "lanalyzer/analysis/visitor_control.py",
        "lanalyzer/analysis/visitor.py",
    ]
    
    for file in expected_files:
        print(f"  Checking {file}...", end="")
        assert os.path.exists(file), f"File does not exist: {file}"
        print("Exists")
    
    print("All file checks successful!")

if __name__ == "__main__":
    print("Starting verification of refactoring results...")
    check_files()
    test_backward_compatibility()
    test_instantiation()
    print("All tests passed! Refactoring successful.") 