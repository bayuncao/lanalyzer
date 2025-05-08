"""
测试新的模块导入结构是否正常工作。
"""


def test_imports():
    """测试导入所有新的组件。"""
    try:
        from lanalyzer.analysis import (
            CallChainBuilder,
            ChainUtils,
            ControlFlowAnalyzer,
            DataFlowAnalyzer,
        )

        print("Successfully imported all components:")
        print(f"- CallChainBuilder: {CallChainBuilder}")
        print(f"- ChainUtils: {ChainUtils}")
        print(f"- ControlFlowAnalyzer: {ControlFlowAnalyzer}")
        print(f"- DataFlowAnalyzer: {DataFlowAnalyzer}")

        # 测试基本实例化
        dummy_tracker = type("DummyTracker", (), {"debug": False})()
        builder = CallChainBuilder(dummy_tracker)

        print(f"\nSuccessfully created CallChainBuilder instance")
        print(f"- builder.data_flow: {builder.data_flow}")
        print(f"- builder.control_flow: {builder.control_flow}")
        print(f"- builder.utils: {builder.utils}")

        return True
    except Exception as e:
        print(f"Error importing components: {e}")
        return False


if __name__ == "__main__":
    test_imports()
