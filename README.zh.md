# LanaLyzer

LanaLyzer 是一个高级的 Python 静态污点分析工具，旨在检测 Python 项目中的潜在安全漏洞。它通过分析从不受信任的数据源（Sources）到敏感操作点（Sinks）的数据流动，提供详细的风险洞察。

## 功能特点

- **污点分析**：跟踪从数据源到汇聚点的数据流。
- **可定制规则**：支持自定义数据源、汇聚点、净化器和污点传播路径。
- **静态分析**：无需执行代码即可完成分析。
- **可扩展性**：轻松添加新规则，检测 SQL 注入、XSS 等漏洞。
- **详细报告**：生成包含漏洞详情和修复建议的全面分析报告。
- **命令行接口**：支持通过终端直接运行分析。

## 安装

### 前置要求
- Python 3.10 或更高版本
- [Poetry](https://python-poetry.org/)（推荐用于依赖管理）

### 安装步骤
1. 克隆仓库：
   ```bash
   git clone https://github.com/mxcrafts/lanalyzer.git
   cd lanalyzer
   ```

2. 安装依赖：
   ```bash
   poetry install
   ```

3. 激活虚拟环境：
   ```bash
   poetry shell
   ```

## 使用方法

### 基本分析
对 Python 文件运行污点分析：
```bash
python -m lanalyzer analyze <目标文件> --config <配置文件>
```

### 命令行选项
- `--config`：配置文件路径。
- `--output`：保存分析报告的路径。
- `--pretty`：美化输出。
- `--detailed`：显示详细的分析统计信息。

### 示例
```bash
python -m lanalyzer analyze example.py --config rules/sql_injection.json --pretty
```

## 贡献

欢迎贡献代码！请参阅 [CONTRIBUTING.md](CONTRIBUTING.md) 文件，了解如何为 LanaLyzer 做出贡献。

## 许可证

本项目基于 MIT 许可证开源。详情请参阅 [LICENSE](LICENSE) 文件。

## 联系方式

如有问题或需要支持，请在 GitHub 上提交 issue 或发送邮件至 [lanalyzer@example.com](mailto:lanalyzer@example.com)。

## 最近更新

- 增强了上下文分析和调用链构建逻辑：修复了在污点分析中源点和汇聚点关联的问题，优先在同一函数内查找源点，避免错误地关联到其他函数中相同的语句。

## MCP 模块使用指南

LanaLyzer 现在支持 Model Context Protocol (MCP)，可以作为 MCP 服务器运行，允许 AI 模型和工具通过标准接口访问污点分析功能。

### 安装 MCP 依赖

如果您使用的是 pip：

```bash
pip install "lanalyzer[mcp]"
```

如果您使用的是 uv：

```bash
uv pip install -e ".[mcp]"
```

### MCP 服务器启动方式

有多种方式可以启动 MCP 服务器：

1. **使用 Python 模块方式**:

```bash
# 查看帮助信息
python -m lanalyzer.mcp --help

# 启动服务器
python -m lanalyzer.mcp run --host 127.0.0.1 --port 8000

# 使用调试模式
python -m lanalyzer.mcp run --debug
```

2. **使用 lanalyzer 命令行工具**:

```bash
# 查看帮助信息
lanalyzer mcp --help

# 启动服务器
lanalyzer mcp run --host 127.0.0.1 --port 8000

# 使用 FastMCP 开发模式
lanalyzer mcp dev
```

### MCP 服务器功能

MCP 服务器提供以下核心功能：

1. **代码分析**：分析 Python 代码字符串中的安全漏洞
2. **文件分析**：分析指定文件中的安全漏洞
3. **路径分析**：分析整个目录或项目中的安全漏洞
4. **漏洞解释**：提供对发现漏洞的详细解释
5. **配置管理**：获取、验证和创建分析配置

### 与 AI 工具集成

MCP 服务器可以与支持 MCP 协议的 AI 工具集成，例如：

```python
# 使用 FastMCP 客户端
from fastmcp import FastMCPClient

# 创建客户端连接到服务器
client = FastMCPClient("http://127.0.0.1:8000")

# 分析代码
result = client.call({
    "type": "analyze_code",
    "code": "user_input = input()\nquery = f\"SELECT * FROM users WHERE name = '{user_input}'\"",
    "file_path": "example.py",
    "config_path": "/path/to/config.json"
})

# 打印分析结果
print(result)
```

### 在 Cursor 中使用

如果您在 Cursor 编辑器中工作，可以直接要求 AI 使用 LanaLyzer 分析代码：

```
请使用 lanalyzer 分析当前文件中的安全漏洞，并解释可能的风险。
```

### 命令行选项

MCP 服务器支持以下命令行选项：

- `--debug`: 启用调试模式，显示详细日志
- `--host`: 设置服务器监听地址（默认：127.0.0.1）
- `--port`: 设置服务器监听端口（默认：8000）

### 高级用法

#### 自定义配置

您可以使用 get_config、validate_config 和 create_config 工具来管理漏洞检测配置：

```python
# 获取默认配置
config = client.call({
    "type": "get_config"
})

# 创建新配置
result = client.call({
    "type": "create_config",
    "config_data": {...},  # 配置数据
    "config_path": "/path/to/save/config.json"  # 可选
})
```

#### 批量文件分析

分析整个项目或目录：

```python
result = client.call({
    "type": "analyze_path",
    "target_path": "/path/to/project",
    "config_path": "/path/to/config.json",
    "output_path": "/path/to/output.json"  # 可选
})
```

## 开始使用