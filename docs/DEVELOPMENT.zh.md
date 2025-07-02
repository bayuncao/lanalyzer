# 开发指南

本文档描述了 lanalyzer 的开发工作流程，包括构建、测试和发布。

## 前置条件

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) 包管理器

## 设置开发环境

1. 克隆仓库：
```bash
git clone <repository-url>
cd lanalyzer
```

2. 安装依赖：
```bash
# 安装基本依赖
make install

# 安装开发依赖
make install-dev

# 安装 MCP 支持
make install-mcp

# 安装所有依赖（开发 + MCP）
make install-all
```

这将安装所有依赖，包括开发工具如 black、isort、flake8、mypy、pytest、build 和 twine。如果需要 MCP 服务器功能，请使用 `make install-mcp` 或 `make install-all`。

## 开发工作流程

### 代码质量

格式化代码：
```bash
make format
```

运行代码检查：
```bash
make lint
```

运行所有质量检查：
```bash
make quality
```

### 测试

运行测试：
```bash
make test
```

运行带覆盖率的测试：
```bash
make test-cov
```

### 构建

清理构建产物：
```bash
make clean
```

构建包：
```bash
make build
```

这会在 `dist/` 目录中创建源分发包（.tar.gz）和轮子文件（.whl）。

## MCP 服务器开发

项目包含 MCP（模型上下文协议）服务器功能，用于与 AI 助手集成。

### 启动 MCP 服务器

```bash
# 在端口 8001 启动 MCP 服务器
make mcp-server

# 以调试模式启动 MCP 服务器
make mcp-server-debug

# 测试 MCP CLI
make mcp-test
```

### MCP 服务器功能

- **代码分析**：分析 Python 文件中的漏洞
- **配置管理**：创建和验证分析配置
- **漏洞解释**：获取发现漏洞的详细解释
- **文件分析**：分析单个文件或整个目录

### MCP 客户端连接

使用 Python 客户端连接到 MCP 服务器时：

1. 正常创建 ClientSession
2. 在任何工具调用之前调用 `await session.initialize()`
3. 等待初始化完成后再发出请求

示例连接 URL：`http://127.0.0.1:8001`

## 发布到 PyPI

### 方法 1：使用 Makefile（简单）

用于基本发布而不进行版本管理：

```bash
# 发布到测试 PyPI
make test-publish

# 发布到主 PyPI
make publish
```

### 方法 2：使用发布脚本（推荐）

发布脚本提供更好的版本管理和安全检查：

#### 试运行（测试而不发布）
```bash
make publish-dry-run
```

#### 版本升级并发布
```bash
# 升级补丁版本（0.1.1 -> 0.1.2）并发布
make publish-patch

# 升级次要版本（0.1.1 -> 0.2.0）并发布
make publish-minor

# 升级主要版本（0.1.1 -> 1.0.0）并发布
make publish-major
```

#### 版本升级并发布（跳过测试）
```bash
# 升级补丁版本并发布（跳过测试）
make publish-patch-no-test

# 升级次要版本并发布（跳过测试）
make publish-minor-no-test

# 升级主要版本并发布（跳过测试）
make publish-major-no-test

# 不升级版本直接发布（跳过测试）
make publish-no-test
```

#### 发布到测试 PyPI
```bash
make publish-test
```

#### 手动版本升级
```bash
# 仅升级补丁版本
make version-patch

# 仅升级次要版本
make version-minor

# 仅升级主要版本
make version-major
```

### 发布脚本选项

发布脚本（`scripts/publish.py`）支持各种选项：

```bash
# 基本用法
uv run python scripts/publish.py

# 带版本升级
uv run python scripts/publish.py --version-bump patch

# 发布到测试 PyPI
uv run python scripts/publish.py --test-pypi

# 跳过各种检查（用于 CI/CD）
uv run python scripts/publish.py --skip-tests --skip-quality --skip-git-check

# 试运行（测试而不发布）
uv run python scripts/publish.py --dry-run
```

## PyPI 凭据

发布前，确保已配置 PyPI 凭据：

1. 在 [PyPI](https://pypi.org) 和 [Test PyPI](https://test.pypi.org) 创建账户
2. 为两个服务生成 API 令牌
3. 使用以下方法之一配置凭据：

### 选项 1：使用 keyring（推荐）
```bash
# 用于主 PyPI
uv run python -m keyring set https://upload.pypi.org/legacy/ __token__

# 用于测试 PyPI
uv run python -m keyring set https://test.pypi.org/legacy/ __token__
```

### 选项 2：使用 .pypirc 文件
创建 `~/.pypirc`：
```ini
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
username = __token__
password = pypi-your-api-token-here

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-your-test-api-token-here
```

## 从 Poetry 迁移到 uv

此项目已从 Poetry 迁移到 uv。主要变化：

1. **依赖管理**：使用 `uv add/remove` 而不是 `poetry add/remove`
2. **虚拟环境**：由 uv 自动管理
3. **脚本**：使用 `uv run` 而不是 `poetry run`
4. **锁定文件**：`uv.lock` 而不是 `poetry.lock`
5. **配置**：依赖在 `pyproject.toml` 的 `[dependency-groups]` 下定义

## 可用的 Make 命令

运行 `make help` 查看所有可用命令：

```bash
make help
```

这将显示：
- `format` - 使用 black 和 isort 格式化代码
- `lint` - 使用 flake8 和 mypy 运行代码检查
- `check` - 运行格式化和代码检查
- `quality` - 运行格式化、代码检查和 pre-commit
- `test` - 运行测试
- `test-cov` - 运行带覆盖率的测试
- `clean` - 清理构建产物
- `build` - 构建包
- `test-publish` - 发布到测试 PyPI
- `publish` - 发布到 PyPI
- `publish-patch` - 升级补丁版本并发布
- `publish-minor` - 升级次要版本并发布
- `publish-major` - 升级主要版本并发布
- `publish-patch-no-test` - 升级补丁版本并发布（跳过测试）
- `publish-minor-no-test` - 升级次要版本并发布（跳过测试）
- `publish-major-no-test` - 升级主要版本并发布（跳过测试）
- `publish-no-test` - 不升级版本直接发布（跳过测试）
- `publish-test` - 带检查发布到测试 PyPI
- `publish-dry-run` - 测试发布过程而不上传
- `install` - 安装依赖
- `install-dev` - 安装开发依赖
- `install-mcp` - 安装 MCP 支持
- `install-all` - 安装开发依赖和 MCP 支持
- `mcp-server` - 在端口 8001 启动 MCP 服务器
- `mcp-server-debug` - 以调试模式启动 MCP 服务器
- `mcp-test` - 测试 MCP CLI
- `version-patch` - 升级补丁版本
- `version-minor` - 升级次要版本
- `version-major` - 升级主要版本

## 故障排除

### 构建问题
- 确保所有依赖已安装：`make install-dev`
- 清理构建产物：`make clean`
- 检查语法错误：`make lint`

### 发布问题
- 验证 PyPI 凭据已配置
- 先用测试 PyPI 测试：`make publish-test`
- 使用试运行测试过程：`make publish-dry-run`

### 质量检查失败
- 运行 `make format` 修复格式问题
- 修复 `make lint` 显示的代码检查错误
- 更新导入并删除未使用的变量
