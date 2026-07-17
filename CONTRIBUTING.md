# 贡献指南

感谢你对 CrypVol 的关注！欢迎任何形式的贡献。

## 🚀 快速开始

1. **Fork** 本仓库
2. 创建特性分支：`git checkout -b feature/my-feature`
3. 提交你的变更：`git commit -m 'feat: add some feature'`
4. 推送到分支：`git push origin feature/my-feature`
5. 提交 Pull Request

## 🛠️ 开发环境

- **SDK**: [.NET 10.0](https://dotnet.microsoft.com/download/dotnet/10.0)
- **IDE**: Rider / VS Code / Visual Studio 2026+
- **操作系统**: Windows / macOS / Linux

```bash
# 克隆仓库
git clone https://github.com/LeeQianXi/CrypVol.git
cd CrypVol

# 还原依赖
dotnet restore

# 构建
dotnet build

# 运行 CLI
dotnet run --project CrypVol.Cli -- --help

# 运行桌面应用
dotnet run --project CrypVol
```

## 📐 代码风格

- 遵循 [C# 代码约定](https://docs.microsoft.com/zh-cn/dotnet/csharp/fundamentals/coding-style/coding-conventions)
- 使用项目已有的 `.sln.DotSettings` 配置（Rider / ReSharper）
- 命名：PascalCase（类/方法）、camelCase（局部变量/参数）
- 优先使用 `nullable enable` 和 `ImplicitUsings`
- 使用 CommunityToolkit.Mvvm 的源生成器进行 MVVM 开发

## 📝 Commit 规范

推荐使用 [Conventional Commits](https://www.conventionalcommits.org/zh-hans/)：

- `feat:` 新功能
- `fix:` Bug 修复
- `docs:` 文档
- `refactor:` 重构
- `test:` 测试
- `chore:` 构建 / 工具

## 🔍 提交前检查

```bash
# 确保代码可构建
dotnet build -c Release

# 运行测试（如果有）
dotnet test
```

## 📂 项目结构

| 项目 | 说明 |
|------|------|
| `CrypVol` | 桌面应用入口（Avalonia Desktop） |
| `CrypVol.Core` | 核心 GUI 逻辑（ViewModels / Views） |
| `CrypVol.Core.Abstract` | 抽象层（接口、自定义控件、服务） |
| `CrypVol.Lib` | 核心库（加密 / 打包 / 解包逻辑） |
| `CrypVol.Cli` | 命令行工具（System.CommandLine） |

## 🐛 报告 Bug

使用 [Bug 报告模板](https://github.com/LeeQianXi/CrypVol/issues/new?template=bug_report.yml) 提交 Issue，请尽量提供：

- 复现步骤
- 期望行为 vs 实际行为
- 操作系统和 .NET 版本

## 💡 功能请求

使用 [功能请求模板](https://github.com/LeeQianXi/CrypVol/issues/new?template=feature_request.yml) 提交，说明使用场景和建议方案。
