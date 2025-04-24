#!/usr/bin/env python3
"""
Enhanced CLI module for LAnaLyzer.

Provides the command-line interface for enhanced taint analysis with 
complete propagation and call chains.
"""

import datetime
import os
import sys
import time
from typing import Any, Dict, List
import json
import ast

from lanalyzer.analysis.enhanced.tracker import EnhancedTaintTracker


def enhanced_cli_main() -> int:
    """
    Main entry point for the Lanalyzer enhanced CLI.

    Returns:
        Exit code
    """
    from lanalyzer.cli.base import create_parser

    parser = create_parser()

    args = parser.parse_args()

    # 设置日志文件
    log_file = None
    original_stdout = sys.stdout
    original_stderr = sys.stderr

    if args.log_file:
        try:
            log_file = open(args.log_file, "w", encoding="utf-8")
            # 重定向标准输出和标准错误到日志文件
            sys.stdout = LogTee(sys.stdout, log_file)
            sys.stderr = LogTee(sys.stderr, log_file)
            print(f"[日志] 开始记录到文件: {args.log_file}")
            print(f"[日志] 时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        except Exception as e:
            print(f"[错误] 无法打开日志文件 {args.log_file}: {e}")
            # 恢复标准输出
            sys.stdout = original_stdout
            sys.stderr = original_stderr

    try:
        # 添加强制性调试输出来帮助识别问题
        print("[启动] Lanalyzer 增强模式启动")
        print(f"[参数] 目标: {args.target}")
        print(f"[参数] 配置文件: {args.config}")
        print(f"[参数] 输出文件: {args.output}")
        print(f"[参数] 调试模式: {args.debug}")
        print(f"[参数] 日志文件: {args.log_file}")

        # 如果开启了list-files，只列出将被分析的文件
        if args.list_files:
            list_target_files(args.target)
            return 0

        # 加载配置
        config = load_configuration(args.config, args.debug)

        # 列出将被分析的文件
        target_files = gather_target_files(args.target)
        if args.debug:
            print(f"[文件列表] 将分析以下 {len(target_files)} 个文件:")
            for idx, file_path in enumerate(target_files, 1):
                print(f"  {idx}. {file_path}")

        # 运行分析
        tracker = EnhancedTaintTracker(config, debug=args.debug)

        # 使用增强的分析函数，支持详细日志
        vulnerabilities = analyze_files_with_logging(
            tracker, target_files, debug=args.debug
        )

        # 保存结果
        if args.output:
            save_output(vulnerabilities, args.output, args.pretty, args.debug)

        # 获取摘要
        summary = tracker.get_summary()
        detailed_summary = tracker.get_detailed_summary(vulnerabilities)

        # 打印基本摘要
        print_summary(summary, vulnerabilities)

        # 打印详细摘要
        print_detailed_summary(detailed_summary)

        # 打印详细漏洞信息
        if vulnerabilities and args.verbose:
            print("\n" + "=" * 60)
            print("DETAILED VULNERABILITY INFORMATION")
            print("-" * 60)
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"\nVulnerability #{i}:")
                tracker.print_detailed_vulnerability(vuln)

        return 0

    except Exception as e:
        if args.debug:
            import traceback

            traceback.print_exc()
        else:
            print(f"Error during analysis: {e}")
        return 1

    finally:
        # 关闭日志文件并恢复标准输出
        if log_file:
            print(f"[日志] 结束时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("[日志] 日志记录完成")
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            log_file.close()


# 添加一个同时输出到控制台和日志文件的类
class LogTee:
    """同时将输出发送到两个文件对象"""

    def __init__(self, file1, file2):
        self.file1 = file1
        self.file2 = file2

    def write(self, data):
        self.file1.write(data)
        self.file2.write(data)
        self.file1.flush()  # 确保实时输出
        self.file2.flush()

    def flush(self):
        self.file1.flush()
        self.file2.flush()


def analyze_files_with_logging(
    tracker: EnhancedTaintTracker, files: List[str], debug: bool = False
) -> List[Dict[str, Any]]:
    """
    分析多个文件并提供详细的日志记录

    Args:
        tracker: 污点分析器实例
        files: 要分析的文件列表
        debug: 是否启用调试模式

    Returns:
        发现的漏洞列表
    """
    import datetime
    import os

    all_vulnerabilities = []
    total_files = len(files)
    start_time = time.time()

    print(f"\n[分析] 开始分析 {total_files} 个文件")
    print(f"[分析] 开始时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # 记录配置信息 - 使用tracker.config而不是直接访问rules
    print(f"[配置] 源点类型: {[s['name'] for s in tracker.sources]}")
    print(f"[配置] 汇点类型: {[s['name'] for s in tracker.sinks]}")
    print(f"[配置] 规则数量: {len(tracker.config.get('rules', []))}")  # 修正这一行

    # 记录特别关注的sink模式
    sink_patterns = []
    for sink in tracker.sinks:
        sink_patterns.extend(sink.get("patterns", []))
    print(f"[配置] 汇点模式: {sink_patterns}")

    # 特别关注with open上下文中的sink点
    with_open_sinks = [p for p in sink_patterns if "load" in p or "loads" in p]
    if with_open_sinks:
        print(f"[配置] 特别关注with open上下文中的sink点: {with_open_sinks}")

    for idx, file_path in enumerate(files, 1):
        file_start_time = time.time()

        try:
            # 打印分析进度
            progress = f"[{idx}/{total_files}]"
            print(f"\n{progress} {'='*50}")
            print(f"{progress} 开始分析文件: {file_path}")
            print(f"{progress} {'='*50}")

            # 打印文件信息
            if os.path.exists(file_path):
                file_size = os.path.getsize(file_path)
                print(f"{progress} 文件大小: {file_size} 字节")

                # 计算文件行数
                try:
                    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                        line_count = content.count("\n") + 1

                    print(f"{progress} 文件行数: {line_count}")

                except Exception as e:
                    print(f"{progress} 读取文件内容时出错: {e}")

            # 执行分析前记录当前时间
            analysis_start = time.time()
            print(f"{progress} 开始执行AST分析...")

            # 分析文件，不管成功与否都继续处理
            try:
                file_vulnerabilities = tracker.analyze_file(file_path)
            except Exception as e:
                print(f"{progress} 分析过程异常: {e}")
                if debug:
                    import traceback
                    print(traceback.format_exc())
                file_vulnerabilities = []  # 出错时设为空列表

            # 记录分析结果
            file_end_time = time.time()
            analysis_duration = file_end_time - file_start_time
            ast_analysis_time = file_end_time - analysis_start

            print(f"{progress} 分析完成，总耗时: {analysis_duration:.2f} 秒")
            print(f"{progress} AST分析耗时: {ast_analysis_time:.2f} 秒")
            print(f"{progress} 发现漏洞数量: {len(file_vulnerabilities)}")

            # 修改这部分：强制进行分析，即使没有visitor
            sources_count = 0
            sinks_count = 0
            
            # 尝试获取源点和汇点信息，但不阻止处理
            if hasattr(tracker, "visitor") and tracker.visitor:
                sources_count = (
                    len(tracker.visitor.found_sources)
                    if hasattr(tracker.visitor, "found_sources")
                    else 0
                )
                sinks_count = (
                    len(tracker.visitor.found_sinks)
                    if hasattr(tracker.visitor, "found_sinks")
                    else 0
                )
                
                print(f"{progress} 发现源点数量: {sources_count}")
                print(f"{progress} 发现汇点数量: {sinks_count}")

                # 记录with open相关的文件句柄
                if hasattr(tracker.visitor, "file_handles"):
                    file_handles = tracker.visitor.file_handles
                    print(f"{progress} 跟踪的文件句柄数量: {len(file_handles)}")

                    # 详细记录每个文件句柄
                    if file_handles:
                        print(f"{progress} 文件句柄详情:")
                        for handle, info in file_handles.items():
                            from_with = info.get("from_with", False)
                            mode = info.get("mode", "unknown")
                            source = info.get("source_var", "unknown")
                            print(
                                f"{progress}   - {handle}: from_with={from_with}, mode={mode}, source={source}"
                            )
            else:
                # 没有visitor时也不中断分析
                print(f"{progress} 注意: 此文件没有可用的visitor信息，将跳过详细分析但仍继续处理")
                
                # 可以在这里添加自定义的分析逻辑，不依赖visitor
                # 例如，使用正则表达式或其他方式查找潜在的问题
                try:
                    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                        # 简单示例：检查是否包含特定的敏感函数调用
                        for pattern in tracker.sinks:
                            for sink_pattern in pattern.get("patterns", []):
                                if sink_pattern in content:
                                    print(f"{progress} 在文件中找到潜在的sink模式: {sink_pattern}")
                except Exception as e:
                    print(f"{progress} 无法读取文件内容进行替代分析: {e}")

            if file_vulnerabilities:
                print(f"{progress} 漏洞详情:")
                for i, vuln in enumerate(file_vulnerabilities, 1):
                    rule = vuln.get("rule", "Unknown")
                    source_name = vuln.get("source", {}).get("name", "Unknown")
                    source_line = vuln.get("source", {}).get("line", 0)
                    sink_name = vuln.get("sink", {}).get("name", "Unknown")
                    sink_line = vuln.get("sink", {}).get("line", 0)
                    tainted_var = vuln.get("tainted_variable", "Unknown")
                    
                    # 检查是否是自动检测的漏洞
                    is_auto_detected = vuln.get("auto_detected", False)
                    
                    if is_auto_detected:
                        print(
                            f"{progress}   {i}. {rule}: [自动检测] {sink_name}(行{sink_line}), 未找到明确来源"
                        )
                    else:
                        print(
                            f"{progress}   {i}. {rule}: {source_name}(行{source_line}) -> {sink_name}(行{sink_line}), 污染变量: {tainted_var}"
                        )
                        
                    # 检查是否是with open上下文中的sink - 修改这部分代码，增加更健壮的检查
                    is_with_open_sink = (
                        "with open" in source_name or "FileRead" in source_name
                    )

                    # 只有当tracker.visitor存在时才检查file_handles
                    if (
                        hasattr(tracker, "visitor")
                        and tracker.visitor
                        and hasattr(tracker.visitor, "file_handles")
                    ):
                        is_with_open_sink = is_with_open_sink or (
                            tainted_var in tracker.visitor.file_handles
                            and tracker.visitor.file_handles[tainted_var].get(
                                "from_with", False
                            )
                        )

                    if is_with_open_sink:
                        print(f"{progress}      ⚠️ 注意: 这是with open上下文中的sink点!")

            all_vulnerabilities.extend(file_vulnerabilities)

        except Exception as e:
            print(f"{progress} 分析文件时出错: {e}")
            if debug:
                import traceback
                print(traceback.format_exc())

    # 打印总结
    end_time = time.time()
    total_duration = end_time - start_time
    print(f"\n[分析] 分析完成，总耗时: {total_duration:.2f} 秒")
    print(f"[分析] 平均每个文件耗时: {total_duration/total_files:.2f} 秒")
    print(f"[分析] 发现漏洞总数: {len(all_vulnerabilities)}")

    # 统计漏洞类型
    vuln_types = {}
    auto_detected_vulns = 0

    for vuln in all_vulnerabilities:
        rule = vuln.get("rule", "Unknown")
        is_auto_detected = vuln.get("auto_detected", False)
        
        if is_auto_detected:
            auto_detected_vulns += 1
        
        vuln_types[rule] = vuln_types.get(rule, 0) + 1

    if vuln_types:
        print("[分析] 漏洞类型统计:")
        for rule, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {rule}: {count}个")
        
        # 显示自动检测的漏洞数量
        if auto_detected_vulns > 0:
            print(f"[分析] 自动检测的潜在漏洞: {auto_detected_vulns}个")

    # 特别统计with open上下文中的sink点漏洞
    with_open_vulns = []
    for vuln in all_vulnerabilities:
        source_name = vuln.get("source", {}).get("name", "")
        tainted_var = vuln.get("tainted_variable", "")
        if "with open" in source_name or "FileRead" in source_name:
            with_open_vulns.append(vuln)

    if with_open_vulns:
        print(f"[分析] 发现 {len(with_open_vulns)} 个与文件操作相关的漏洞")
        for i, vuln in enumerate(with_open_vulns, 1):
            file = vuln.get("file", "Unknown")
            sink_line = vuln.get("sink", {}).get("line", 0)
            rule = vuln.get("rule", "Unknown")
            print(f"  {i}. {os.path.basename(file)}:{sink_line} - {rule}")

    print(f"[分析] 结束时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    return all_vulnerabilities


def print_summary(
    summary: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]
) -> None:
    """
    Print a detailed summary of the analysis results.

    Args:
        summary: Analysis summary dictionary
        vulnerabilities: List of vulnerability dictionaries
    """
    print("\n" + "=" * 60)
    print("ENHANCED TAINT ANALYSIS RESULTS")
    print("-" * 60)
    print(f"Files analyzed: {summary.get('files_analyzed', 0)}")
    print(f"Functions analyzed: {summary.get('functions_analyzed', 0)}")
    print(f"Vulnerabilities found: {len(vulnerabilities)}")

    if len(vulnerabilities) > 0:
        print("-" * 60)
        print("VULNERABILITIES BY TYPE:")
        rules = {}
        for vuln in vulnerabilities:
            rule = vuln.get("rule", "Unknown")
            rules[rule] = rules.get(rule, 0) + 1

        for rule, count in sorted(rules.items(), key=lambda x: x[1], reverse=True):
            print(f"  {rule}: {count}")

        print("\nTOP 5 AFFECTED FILES:")
        files = {}
        for vuln in vulnerabilities:
            file = vuln.get("file", "Unknown")
            files[file] = files.get(file, 0) + 1

        for file, count in sorted(files.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {os.path.basename(file)}: {count}")

    print("=" * 60)


def print_detailed_summary(detailed_summary: Dict[str, Any]) -> None:
    """Print detailed analysis summary with advanced statistics."""
    print("\n" + "=" * 60)
    print("DETAILED ANALYSIS STATISTICS")
    print("-" * 60)

    # 基本统计
    print(f"Files analyzed: {detailed_summary.get('files_analyzed', 0)}")
    print(f"Functions analyzed: {detailed_summary.get('functions_analyzed', 0)}")
    print(f"Vulnerabilities found: {detailed_summary.get('vulnerabilities_found', 0)}")

    # 传播链统计
    print("\nPROPAGATION STATISTICS:")
    print(
        f"Vulnerabilities with propagation chains: {detailed_summary.get('vulnerabilities_with_propagation', 0)}"
    )
    print(
        f"Average propagation steps: {detailed_summary.get('average_propagation_steps', 0)}"
    )
    print(f"Max propagation steps: {detailed_summary.get('max_propagation_steps', 0)}")
    print(f"Min propagation steps: {detailed_summary.get('min_propagation_steps', 0)}")

    # 调用链统计
    print("\nCALL CHAIN STATISTICS:")
    print(
        f"Vulnerabilities with call chains: {detailed_summary.get('vulnerabilities_with_call_chains', 0)}"
    )
    print(
        f"Average call chain length: {detailed_summary.get('average_call_chain_length', 0)}"
    )
    print(f"Max call chain length: {detailed_summary.get('max_call_chain_length', 0)}")
    print(f"Min call chain length: {detailed_summary.get('min_call_chain_length', 0)}")

    # 源点统计
    source_counts = detailed_summary.get("source_counts", {})
    if source_counts:
        print("\nSOURCE TYPE STATISTICS:")
        for source, count in sorted(
            source_counts.items(), key=lambda x: x[1], reverse=True
        ):
            print(f"  {source}: {count}")

    # 汇点统计
    sink_counts = detailed_summary.get("sink_counts", {})
    if sink_counts:
        print("\nSINK TYPE STATISTICS:")
        for sink, count in sorted(
            sink_counts.items(), key=lambda x: x[1], reverse=True
        ):
            print(f"  {sink}: {count}")

    # 源点-汇点对统计
    source_sink_pairs = detailed_summary.get("source_sink_pairs", {})
    if source_sink_pairs:
        print("\nTOP SOURCE-SINK PAIRS:")
        for pair, count in sorted(
            source_sink_pairs.items(), key=lambda x: x[1], reverse=True
        )[
            :10
        ]:  # 只显示前10个
            print(f"  {pair}: {count}")

    print("=" * 60)


# 添加新函数来帮助调试
def list_target_files(target_path):
    """列出目标路径中的所有Python文件"""
    import os

    print(f"[文件列表] 目标路径: {target_path}")
    if not os.path.exists(target_path):
        print(f"[错误] 目标路径不存在: {target_path}")
        return

    if os.path.isdir(target_path):
        for root, dirs, files in os.walk(target_path):
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    print(f"[文件列表] 发现Python文件: {full_path}")
    else:
        print(f"[文件列表] 单个文件: {target_path}")


def search_for_file(base_dir, filename):
    """搜索特定文件"""
    import os

    print(f"[搜索] 在 {base_dir} 中搜索 {filename}...")
    found_locations = []

    if os.path.isdir(base_dir):
        for root, dirs, files in os.walk(base_dir):
            if filename in files:
                found_locations.append(os.path.join(root, filename))

    if found_locations:
        print(f"[搜索] 在以下位置找到 {filename}:")
        for loc in found_locations:
            print(f"  - {loc}")
    else:
        print(f"[搜索] 未能找到 {filename}")


def gather_target_files(target_path):
    """收集要分析的目标文件列表"""
    import os

    if not os.path.exists(target_path):
        print(f"[错误] 目标路径不存在: {target_path}")
        return []

    if os.path.isdir(target_path):
        target_files = []
        for root, dirs, files in os.walk(target_path):
            for file in files:
                if file.endswith(".py"):
                    target_files.append(os.path.join(root, file))
        return target_files
    else:
        # 单个文件
        if target_path.endswith(".py"):
            return [target_path]
        else:
            print(f"[警告] 目标不是Python文件: {target_path}")
            return []


def load_configuration(config_path, debug=False):
    """加载配置文件"""
    import json
    import os

    if debug:
        print(f"[配置] 加载配置文件: {config_path}")

    if not config_path:
        print("[错误] 未提供配置文件路径")
        raise ValueError("必须提供配置文件路径")

    if not os.path.exists(config_path):
        print(f"[错误] 配置文件不存在: {config_path}")
        raise FileNotFoundError(f"配置文件不存在: {config_path}")

    try:
        with open(config_path, "r") as f:
            config = json.load(f)
            if debug:
                print("[配置] 成功加载配置，包含:")
                print(f"  - {len(config.get('sources', []))} 个污点源")
                print(f"  - {len(config.get('sinks', []))} 个污点汇")
                print(f"  - {len(config.get('rules', []))} 个规则")
            return config
    except json.JSONDecodeError as e:
        print(f"[错误] 配置文件 {config_path} 包含无效的 JSON: {e}")
        raise
    except Exception as e:
        print(f"[错误] 加载配置文件失败: {e}")
        raise


def save_output(vulnerabilities, output_path, pretty=False, debug=False):
    """保存分析结果到文件"""
    import json

    if not output_path:
        return

    if debug:
        print(f"[输出] 保存结果到: {output_path}")

    try:
        # 预处理结果已经实现，现在添加ensure_ascii=False
        with open(output_path, "w", encoding="utf-8") as f:
            if pretty:
                json.dump(vulnerabilities, f, indent=2, ensure_ascii=False)
            else:
                json.dump(vulnerabilities, f, ensure_ascii=False)

        if debug:
            print(f"[输出] 成功保存 {len(vulnerabilities)} 个漏洞结果到 {output_path}")
    except Exception as e:
        print(f"[错误] 保存输出失败: {e}")
        if debug:
            import traceback
            print(traceback.format_exc())


def prepare_for_json(obj):
    """
    递归处理对象，使其可以序列化为JSON。
    
    处理：
    - AST节点转换为字符串表示
    - 集合(set)转换为列表
    - 其他不可序列化对象转换为字符串
    
    Args:
        obj: 要处理的对象
        
    Returns:
        可序列化的对象
    """
    if isinstance(obj, ast.AST):
        # 处理AST节点
        return f"<{obj.__class__.__name__}>"
    elif isinstance(obj, dict):
        # 递归处理字典
        return {k: prepare_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        # 递归处理列表和元组
        return [prepare_for_json(item) for item in obj]
    elif isinstance(obj, set):
        # 处理集合
        return [prepare_for_json(item) for item in obj]
    elif hasattr(obj, '__dict__'):
        # 处理自定义对象
        return f"<{obj.__class__.__name__}>"
    else:
        # 尝试直接返回，如果不可序列化，则转为字符串
        try:
            json.dumps(obj)
            return obj
        except (TypeError, OverflowError):
            return str(obj)


if __name__ == "__main__":
    sys.exit(enhanced_cli_main())
