#!/usr/bin/env python3
"""
Lanalyzer MCP客户端示例

此示例演示如何使用MCP客户端访问Lanalyzer MCP服务器的功能。
请先确保已经启动Lanalyzer MCP服务器（lanalyzer mcp）。
"""

import json
import sys
import requests
import os
from typing import Dict, Any, List


class SimpleMCPClient:
    """简单的MCP客户端实现"""

    def __init__(self, server_url: str = "http://localhost:8000/.well-known/mcp/v1"):
        """
        初始化MCP客户端

        Args:
            server_url: MCP服务器URL
        """
        self.server_url = server_url
        # 检查服务器连接
        self._check_server()

    def _check_server(self) -> None:
        """检查服务器连接"""
        try:
            response = self._make_request({"type": "server_info"})
            print(
                f"已连接到MCP服务器: {response.get('server', {}).get('name')} v{response.get('server', {}).get('version')}"
            )
            print(f"服务器描述: {response.get('server', {}).get('description')}")
            print(
                f"服务器功能: {', '.join(response.get('server', {}).get('capabilities', []))}"
            )
        except Exception as e:
            print(f"无法连接到MCP服务器: {e}")
            sys.exit(1)

    def _make_request(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        发送MCP请求

        Args:
            data: 请求数据

        Returns:
            响应数据
        """
        try:
            response = requests.post(self.server_url, json=data)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"请求失败: {e}")
            raise

    def analyze_code(self, code: str, file_path: str = "example.py") -> Dict[str, Any]:
        """
        分析代码

        Args:
            code: 要分析的Python代码
            file_path: 文件路径

        Returns:
            分析结果
        """
        request_data = {
            "type": "analyze",
            "code": code,
            "file_path": file_path,
            "options": {"debug": True},
        }

        response = self._make_request(request_data)
        return response

    def analyze_path(
        self, target_path: str, config_path: str = None, output_path: str = None
    ) -> Dict[str, Any]:
        """
        分析文件或目录

        Args:
            target_path: 要分析的文件或目录路径
            config_path: 配置文件路径（可选）
            output_path: 输出文件路径（可选）

        Returns:
            分析结果
        """
        request_data = {
            "type": "analyze_path",
            "target_path": target_path,
            "config_path": config_path,
            "output_path": output_path,
            "options": {"debug": True},
        }

        response = self._make_request(request_data)
        return response

    def explain_vulnerabilities(
        self, analysis_file: str, format: str = "text", level: str = "detailed"
    ) -> Dict[str, Any]:
        """
        解释漏洞分析结果

        Args:
            analysis_file: 分析结果文件路径
            format: 格式（text或markdown）
            level: 详细程度（brief或detailed）

        Returns:
            漏洞解释结果
        """
        request_data = {
            "type": "explain_vulnerabilities",
            "analysis_file": analysis_file,
            "format": format,
            "level": level,
        }

        response = self._make_request(request_data)
        return response

    def get_configuration(self, config_path: str = None) -> Dict[str, Any]:
        """
        获取配置

        Args:
            config_path: 配置文件路径

        Returns:
            配置数据
        """
        request_data = {
            "type": "configuration",
            "operation": "get",
            "config_path": config_path,
        }

        response = self._make_request(request_data)
        return response


def main():
    """主函数"""
    # 创建MCP客户端
    client = SimpleMCPClient()

    # 获取配置
    print("\n获取配置：")
    config_response = client.get_configuration()
    if config_response.get("success"):
        print("配置获取成功！")
        # 打印配置摘要
        config = config_response.get("config", {})
        print(f"- 源点数量: {len(config.get('sources', []))}")
        print(f"- 汇聚点数量: {len(config.get('sinks', []))}")
        print(f"- 规则数量: {len(config.get('rules', []))}")
        print(f"- 净化器数量: {len(config.get('sanitizers', []))}")
    else:
        print(f"配置获取失败: {config_response.get('errors')}")

    # 分析代码示例
    print("\n分析代码示例：")
    code_samples = [
        # Pickle反序列化示例
        {
            "name": "Pickle反序列化漏洞示例",
            "code": """
import pickle
import base64

def process_data(user_data):
    # 不安全的反序列化操作
    decoded_data = base64.b64decode(user_data)
    return pickle.loads(decoded_data)  # 安全漏洞：不安全的反序列化

# 模拟用户输入
user_input = get_user_input()
result = process_data(user_input)
""",
        },
        # SQL注入示例
        {
            "name": "SQL注入漏洞示例",
            "code": """
import sqlite3

def get_user(username):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # 不安全的SQL查询
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)  # 安全漏洞：SQL注入
    
    return cursor.fetchone()

# 模拟用户输入
user_input = request.args.get('username')
user = get_user(user_input)
""",
        },
    ]

    # 分析每个代码示例
    for i, sample in enumerate(code_samples, 1):
        print(f"\n{i}. {sample['name']}:")
        result = client.analyze_code(sample["code"], f"example_{i}.py")

        if result.get("success"):
            vulnerabilities = result.get("vulnerabilities", [])
            if vulnerabilities:
                print(f"发现 {len(vulnerabilities)} 个漏洞:")
                for j, vuln in enumerate(vulnerabilities, 1):
                    print(f"  {j}. {vuln.get('rule_name')}: {vuln.get('message')}")
                    print(f"     位置: {vuln.get('file_path')}:{vuln.get('line')}")
            else:
                print("未发现漏洞")
        else:
            print(f"分析失败: {result.get('errors')}")

    # 演示文件分析
    print("\n文件分析示例：")
    files_to_analyze = ["examples/shm_broadcast.py"]

    for file_path in files_to_analyze:
        if os.path.exists(file_path):
            print(f"\n分析文件: {file_path}")
            output_path = f"examples/analysis_{os.path.basename(file_path).replace('.py', '')}.json"

            result = client.analyze_path(file_path, output_path=output_path)

            if result.get("success"):
                vulnerabilities = result.get("vulnerabilities", [])
                if vulnerabilities:
                    print(f"发现 {len(vulnerabilities)} 个漏洞")
                    print(f"分析结果已保存到: {result.get('summary', {}).get('output_file')}")

                    # 解释漏洞
                    print("\n漏洞解释:")
                    explain_result = client.explain_vulnerabilities(
                        output_path, format="text", level="detailed"
                    )

                    if explain_result.get("success"):
                        print("=" * 80)
                        print(explain_result.get("explanation"))
                        print("=" * 80)
                    else:
                        print(f"解释漏洞失败: {explain_result.get('errors')}")
                else:
                    print("未发现漏洞")
            else:
                print(f"分析失败: {result.get('errors')}")
        else:
            print(f"文件不存在: {file_path}")


if __name__ == "__main__":
    main()
