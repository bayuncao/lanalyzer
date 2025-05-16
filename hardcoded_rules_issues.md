# LanaLyzer 硬编码规则问题报告

在对 LanaLyzer 项目进行代码审查后，我发现了几处硬编码的规则定义，这与"基于配置文件的污点分析传播工具"的设计理念不符。以下是发现的问题及建议的解决方案。

## 1. 硬编码的漏洞类型映射

**文件：** `ast_parser.py`
**方法：** `_get_sink_vulnerability_type`
**问题：** 该方法定义了一个硬编码的字典，将汇点类型映射到漏洞类型：

```python
vulnerability_map = {
    "SQLQuery": "SQL Injection",
    "CommandExecution": "Command Injection",
    "FileOperation": "Path Traversal",
    "ResponseData": "Cross-Site Scripting",
    "TemplateOperation": "Template Injection",
    "Deserialization": "Deserialization Attack",
    "XMLOperation": "XXE Injection",
}
```

**建议解决方案：** 将漏洞类型映射移到配置文件中，例如：

```json
{
  "vulnerability_types": {
    "SQLQuery": "SQL Injection",
    "CommandExecution": "Command Injection",
    "FileOperation": "Path Traversal",
    "ResponseData": "Cross-Site Scripting",
    "TemplateOperation": "Template Injection",
    "Deserialization": "Deserialization Attack",
    "XMLOperation": "XXE Injection"
  }
}
```

## 2. 硬编码的污点传播规则

**文件：** `visitor_base.py`
**方法：** `_initialize_operation_taint_rules`
**问题：** 此方法定义了大量硬编码的污点传播规则，包括字符串方法、容器方法和数据处理方法：

```python
rules = {}
string_propagating_methods = [
    "strip", "lstrip", "rstrip", "upper", "lower", "title",
    "capitalize", "swapcase", "replace", "format", "join",
    "split", "rsplit", "splitlines", "partition", "rpartition",
]
for method in string_propagating_methods:
    rules[f"str.{method}"] = lambda node, source_info: source_info
container_propagating_methods = ["copy", "items", "keys", "values"]
for method in container_propagating_methods:
    rules[f"dict.{method}"] = lambda node, source_info: source_info
    rules[f"list.{method}"] = lambda node, source_info: source_info
data_propagating_methods = [
    "numpy", "tobytes", "tensor", "array", "astype", "decode", "encode",
]
for method in data_propagating_methods:
    rules[method] = lambda node, source_info: source_info
```

**建议解决方案：** 将这些规则移到配置文件中，例如：

```json
{
  "operation_taint_rules": {
    "string_methods": [
      "strip", "lstrip", "rstrip", "upper", "lower", "title", 
      "capitalize", "swapcase", "replace", "format", "join",
      "split", "rsplit", "splitlines", "partition", "rpartition"
    ],
    "container_methods": {
      "dict": ["copy", "items", "keys", "values"],
      "list": ["copy", "items", "keys", "values"]
    },
    "data_methods": [
      "numpy", "tobytes", "tensor", "array", "astype", "decode", "encode"
    ]
  }
}
```

## 3. 硬编码的危险函数模式

**文件：** `utils.py`
**方法：** `extract_operation_at_line`
**问题：** 该方法定义了硬编码的危险函数模式字典：

```python
dangerous_patterns = {
    "PickleDeserialization": [
        "pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load",
    ],
    "CommandExecution": [
        "os.system", "subprocess.run", "subprocess.Popen", "exec(", "eval(",
    ],
    "SQLInjection": [
        "execute(", "executemany(", "cursor.execute", "raw_connection",
    ],
    "PathTraversal": ["open(", "os.path.join", "os.makedirs", "os.listdir"],
    "XSS": ["render_template", "render", "html"],
}
```

**建议解决方案：** 将这些危险模式移到配置文件中，例如：

```json
{
  "dangerous_patterns": {
    "PickleDeserialization": [
      "pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load"
    ],
    "CommandExecution": [
      "os.system", "subprocess.run", "subprocess.Popen", "exec(", "eval("
    ],
    "SQLInjection": [
      "execute(", "executemany(", "cursor.execute", "raw_connection"
    ],
    "PathTraversal": ["open(", "os.path.join", "os.makedirs", "os.listdir"],
    "XSS": ["render_template", "render", "html"]
  }
}
```

## 总结

将这些硬编码的规则移到配置文件中有以下优点：

1. **增强灵活性**：用户可以根据需要自定义规则，而无需修改代码
2. **提高可维护性**：规则和逻辑分离，让代码更清晰
3. **易于扩展**：添加新的规则只需更新配置文件
4. **一致性**：与"基于配置文件的污点分析工具"设计理念一致

在实现上，可以添加一个新的配置区域来存储这些规则，或者把它们添加到现有的源点和汇点配置中。 