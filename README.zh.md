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

## 开始使用