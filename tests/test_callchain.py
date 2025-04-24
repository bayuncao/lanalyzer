import unittest
import os
import sys
import json
from pathlib import Path

# 添加项目根目录到 Python 路径
current_dir = Path(__file__).parent
project_root = current_dir.parent
sys.path.append(str(project_root))

from lanalyzer.analysis.tracker import EnhancedTaintTracker


class TestCallChainEnhancement(unittest.TestCase):
    """
    测试调用链增强功能
    """

    def setUp(self):
        # 设置基本配置
        self.config = {
            "sources": [
                {
                    "name": "UserInput",
                    "patterns": [
                        "input",
                        "request.args",
                        "request.form",
                        "request.json",
                    ],
                }
            ],
            "sinks": [
                {
                    "name": "PickleDeserialization",
                    "patterns": ["pickle.loads", "pickle.load"],
                },
                {
                    "name": "CommandExecution",
                    "patterns": ["os.system", "subprocess.run", "exec", "eval"],
                },
            ],
            "rules": [
                {
                    "name": "PickleDeserializationVulnerability",
                    "sources": ["UserInput"],
                    "sinks": ["PickleDeserialization"],
                    "message": "Potential vulnerability found: {source} to {sink}",
                }
            ],
        }

        # 创建一个带有调试功能的追踪器
        self.tracker = EnhancedTaintTracker(self.config, debug=True)

        # 准备示例文件目录
        self.examples_dir = project_root / "examples"

    def test_extract_operation_at_line(self):
        """测试语句提取功能"""
        # 创建一个临时文件进行测试
        from lanalyzer.analysis.ast_parser import ParentNodeVisitor
        from lanalyzer.analysis.visitor import EnhancedTaintAnalysisVisitor
        import ast

        # 示例代码
        code = """
def unsafe_func(user_data):
    import pickle
    # 这是一个危险操作
    result = pickle.loads(user_data)  # line 4
    return result

def process_data(data):
    return unsafe_func(data)
        """

        # 使用 AST 解析
        tree = ast.parse(code)
        parent_visitor = ParentNodeVisitor()
        parent_visitor.visit(tree)

        # 创建访问者
        visitor = EnhancedTaintAnalysisVisitor(
            parent_map=parent_visitor.parent_map, debug=True, file_path="test_file.py"
        )
        visitor.source_lines = code.splitlines()

        # 测试方法
        operation = self.tracker._extract_operation_at_line(visitor, 4)
        self.assertIsNotNone(operation)
        self.assertIn("pickle.loads", operation)

        # 测试上下文提取
        stmt_info = self.tracker._get_statement_at_line(visitor, 4, context_lines=1)
        self.assertIn("pickle.loads", stmt_info["statement"])
        self.assertEqual(2, len(stmt_info["context_lines"] or []))

    def test_parallel_state_analysis(self):
        """测试对示例文件的分析"""
        # 确保示例文件存在
        example_file = self.examples_dir / "parallel_state.py"
        if not example_file.exists():
            self.skipTest(f"Example file {example_file} not found")

        # 运行分析
        vulnerabilities = self.tracker.analyze_file(str(example_file))

        # 检查是否找到漏洞
        self.assertTrue(len(vulnerabilities) > 0)

        # 检查调用链是否包含语句信息
        for vuln in vulnerabilities:
            self.assertIn("call_chain", vuln)
            for call_item in vuln["call_chain"]:
                # 检查语句字段是否已添加
                self.assertIn("statement", call_item)

                # 如果有上下文行，则确保它们是有效的
                if "context_lines" in call_item:
                    self.assertIsNotNone(call_item["context_lines"])

        # 打印第一个漏洞的调用链（用于调试）
        if vulnerabilities:
            print("\n测试结果：发现的第一个漏洞的调用链:")
            for i, call_item in enumerate(vulnerabilities[0]["call_chain"]):
                print(f"  [{i}] {call_item['function']} @ 行 {call_item['line']}")
                print(f"      语句: {call_item['statement']}")
                if "context_lines" in call_item:
                    print(f"      上下文: {call_item['context_lines']}")
                print(f"      类型: {call_item['type']}")
                print(f"      描述: {call_item['description']}")


if __name__ == "__main__":
    unittest.main()
