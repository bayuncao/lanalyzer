# 分析结果输出格式

本文档详细描述了 Lanalyzer 漏洞分析返回的 JSON 输出格式结构。

## 概览

分析结果以 JSON 格式返回，包含以下主要部分：

- **`vulnerabilities`**: 检测到的安全漏洞列表
- **`call_chains`**: 从源到汇的数据流路径
- **`summary`**: 分析统计信息和概览
- **`imports`**: 分析文件的导入信息

## 根级字段

```json
{
  "vulnerabilities": [...],
  "call_chains": [...],
  "summary": {...},
  "imports": {...}
}
```

## 漏洞数组

每个漏洞对象包含：

- **`type`** (字符串): 漏洞类型（如 "UnsafeDeserialization"、"PathTraversal"、"CodeInjection"）
- **`severity`** (字符串): 风险级别（"High"、"Medium"、"Low"）
- **`detection_method`** (字符串): 漏洞检测方法（"sink_detection"、"taint_flow"）
- **`sink`** (对象): 危险操作的信息
  - **`name`** (字符串): 汇点类型名称
  - **`line`** (数字): 汇点所在行号
  - **`file`** (字符串): 包含汇点的文件路径
  - **`function_name`** (字符串): 包含汇点的函数
  - **`full_name`** (字符串): 汇点的完全限定名
- **`argument`** (字符串): 传递给汇点的参数
- **`argument_index`** (数字): 危险参数的索引（未知时为 -1）
- **`description`** (字符串): 漏洞的可读描述
- **`recommendation`** (字符串): 建议的缓解措施

### 漏洞示例

```json
{
  "type": "UnsafeDeserialization",
  "severity": "High",
  "detection_method": "sink_detection",
  "sink": {
    "name": "PickleDeserialization",
    "line": 15,
    "file": "example.py",
    "function_name": "load_data",
    "full_name": "pickle.loads"
  },
  "argument": "user_data",
  "argument_index": 0,
  "description": "使用 pickle.loads 对用户控制的数据进行不安全反序列化",
  "recommendation": "使用 JSON 等安全的序列化格式，或在反序列化前验证数据"
}
```

## 调用链数组

每个调用链代表一个数据流路径：

- **`id`** (数字): 调用链的唯一标识符
- **`source`** (对象): 数据源信息
  - **`type`** (字符串): 源类型（如 "NetworkInput"、"UserInput"）
  - **`line`** (数字): 源的行号
  - **`file`** (字符串): 包含源的文件路径
  - **`function`** (字符串): 包含源的函数
- **`sink`** (对象): 数据汇信息
  - **`type`** (字符串): 汇类型（如 "PickleDeserialization"、"FileWrite"）
  - **`line`** (数字): 汇的行号
  - **`file`** (字符串): 包含汇的文件路径
  - **`function`** (字符串): 包含汇的函数
  - **`full_name`** (字符串): 汇的完全限定名
- **`tainted_variable`** (字符串): 携带污染数据的变量名
- **`vulnerability_type`** (字符串): 此流代表的漏洞类型
- **`flow_description`** (字符串): 数据流的可读描述
- **`path_analysis`** (对象): 流路径分析
  - **`path_length`** (数字): 流中的步骤数
  - **`confidence`** (数字): 置信度分数（0.0 到 1.0）
  - **`intermediate_steps`** (数字): 中间处理步骤数
  - **`complexity`** (字符串): 路径复杂度（"low"、"medium"、"high"）
- **`intermediate_nodes`** (数组): 中间处理步骤列表

### 调用链示例

```json
{
  "id": 1,
  "source": {
    "type": "NetworkInput",
    "line": 5,
    "file": "example.py",
    "function": "handle_request"
  },
  "sink": {
    "type": "PickleDeserialization",
    "line": 15,
    "file": "example.py",
    "function": "load_data",
    "full_name": "pickle.loads"
  },
  "tainted_variable": "user_data",
  "vulnerability_type": "UnsafeDeserialization",
  "flow_description": "用户输入从网络请求流向 pickle 反序列化",
  "path_analysis": {
    "path_length": 3,
    "confidence": 0.9,
    "intermediate_steps": 1,
    "complexity": "medium"
  },
  "intermediate_nodes": [
    {
      "line": 10,
      "function": "process_data",
      "operation": "assignment"
    }
  ]
}
```

## 摘要对象

摘要提供整体分析统计信息：

- **`files_analyzed`** (数字): 处理的文件数
- **`functions_found`** (数字): 发现的函数总数
- **`tainted_variables`** (数字): 参与污点流的变量数
- **`sources_found`** (数字): 识别的数据源总数
- **`sinks_found`** (数字): 识别的数据汇总数
- **`vulnerabilities_found`** (数字): 检测到的漏洞总数
- **`imports`** (对象): 导入统计信息
- **`call_chains`** (对象): 调用链统计信息

### 导入统计信息

- **`total_imports`** (数字): 总导入语句数
- **`unique_stdlib_modules`** (数字): 唯一标准库模块数
- **`unique_third_party_modules`** (数字): 唯一第三方模块数
- **`unique_functions`** (数字): 唯一导入函数数
- **`unique_classes`** (数字): 唯一导入类数
- **`stdlib_modules`** (数组): 标准库模块列表
- **`third_party_modules`** (数组): 第三方模块列表
- **`imported_functions`** (数组): 导入函数列表
- **`imported_classes`** (数组): 导入类列表

### 调用链统计信息

- **`total_paths`** (数字): 数据流路径总数
- **`average_path_length`** (数字): 流路径平均长度
- **`high_confidence_paths`** (数字): 高置信度路径数
- **`complex_paths`** (数字): 复杂路径数
- **`tracked_variables`** (数字): 流中跟踪的变量数
- **`tracked_functions`** (数字): 流中涉及的函数数
- **`data_flow_edges`** (数字): 总数据流连接数

## 导入对象

每个文件的导入信息：

- **`<文件路径>`** (对象): 每个分析文件的导入详情
  - **`total_imports`** (数字): 此文件中的总导入数
  - **`unique_modules`** (数字): 导入的唯一模块数
  - **`standard_library_modules`** (数组): 使用的标准库模块
  - **`third_party_modules`** (数组): 使用的第三方模块
  - **`imported_functions`** (数组): 导入的函数
  - **`imported_classes`** (数组): 导入的类
  - **`detailed_imports`** (数组): 详细导入信息

### 详细导入信息

每个详细导入条目包含：

- **`type`** (字符串): 导入类型（"import"、"from_import"）
- **`module`** (字符串): 模块名
- **`imported_name`** (字符串|null): 具体导入名称
- **`alias`** (字符串|null): 导入别名
- **`line`** (数字): 导入的行号
- **`col`** (数字): 导入的列号
- **`is_stdlib`** (布尔值): 是否为标准库模块
- **`root_module`** (字符串): 根模块名

## 完整示例

```json
{
  "vulnerabilities": [
    {
      "type": "UnsafeDeserialization",
      "severity": "High",
      "detection_method": "taint_flow",
      "sink": {
        "name": "PickleDeserialization",
        "line": 15,
        "file": "example.py",
        "function_name": "load_data",
        "full_name": "pickle.loads"
      },
      "argument": "user_data",
      "argument_index": 0,
      "description": "对用户控制数据的不安全反序列化",
      "recommendation": "使用 JSON 等安全的序列化格式"
    }
  ],
  "call_chains": [
    {
      "id": 1,
      "source": {
        "type": "NetworkInput",
        "line": 5,
        "file": "example.py",
        "function": "handle_request"
      },
      "sink": {
        "type": "PickleDeserialization",
        "line": 15,
        "file": "example.py",
        "function": "load_data",
        "full_name": "pickle.loads"
      },
      "tainted_variable": "user_data",
      "vulnerability_type": "UnsafeDeserialization",
      "flow_description": "网络输入流向 pickle 反序列化",
      "path_analysis": {
        "path_length": 2,
        "confidence": 0.95,
        "intermediate_steps": 0,
        "complexity": "low"
      },
      "intermediate_nodes": []
    }
  ],
  "summary": {
    "files_analyzed": 1,
    "functions_found": 3,
    "tainted_variables": 1,
    "sources_found": 1,
    "sinks_found": 1,
    "vulnerabilities_found": 1,
    "imports": {
      "total_imports": 3,
      "unique_stdlib_modules": 2,
      "unique_third_party_modules": 1,
      "stdlib_modules": ["pickle", "json"],
      "third_party_modules": ["requests"]
    },
    "call_chains": {
      "total_paths": 1,
      "average_path_length": 2.0,
      "high_confidence_paths": 1,
      "complex_paths": 0
    }
  },
  "imports": {
    "example.py": {
      "total_imports": 3,
      "unique_modules": 3,
      "standard_library_modules": ["pickle", "json"],
      "third_party_modules": ["requests"],
      "detailed_imports": [
        {
          "type": "import",
          "module": "pickle",
          "imported_name": null,
          "alias": null,
          "line": 1,
          "col": 0,
          "is_stdlib": true,
          "root_module": "pickle"
        }
      ]
    }
  }
}
```
