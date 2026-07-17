# CrypVol — 加密分卷归档工具

[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![Avalonia](https://img.shields.io/badge/Avalonia-11.3-8B5CF6)](https://avaloniaui.net/)
[![License](https://img.shields.io/badge/license-LGPLv2.1-blue)](LICENSE)

**CrypVol**（Cryptographic Volume Package）是一个跨平台的加密分卷打包 / 还原工具，支持将任意文件或目录打包为带加密保护的 `.cvp` 数据卷，并提供配套的 `.cvk` 密钥文件管理。

## ✨ 特性

- 🔐 **多层加密支持** — PlainKey / 密码（Argon2id + AES-GCM）/ 非对称（RSA/ECC）三种模式
- 📦 **分卷存储** — 自动将大数据切分为指定大小的卷（`.cvp`），便于传输和存储
- 🗜️ **GZip 压缩** — 可选数据压缩，减少存储空间
- ⚡ **并行处理** — 多线程并行压缩 / 加密，充分利用多核 CPU
- 🖥️ **GUI + CLI** — 基于 Avalonia 的跨平台桌面界面 + 功能完整的命令行工具
- 🌐 **跨平台** — Windows / macOS / Linux 全平台支持
- 🔍 **内容浏览** — 无需完整解压即可浏览卷内文件列表
- 📋 **灵活过滤** — 支持 Glob 模式的文件包含 / 排除规则

## 📥 安装

### 下载预编译版本

前往 [Releases](https://github.com/LeeQianXi/CrypVol/releases) 页面下载对应平台的二进制包。

### 从源码构建

```bash
git clone https://github.com/LeeQianXi/CrypVol.git
cd CrypVol
dotnet build -c Release
```

## 🚀 快速开始

### CLI 命令行

```bash
# 打包目录为加密卷（密码模式）
CrypVol pack /path/to/data -m Password -p "your-password" -o /output/dir

# 打包并压缩，每个卷 512MB
CrypVol pack /path/to/data -m Password -p "your-password" -s 512 -c

# 仅包含特定文件类型
CrypVol pack /path/to/data --include "**/*.jpg" --include "**/*.png"

# 解包还原
CrypVol extract /output/dir/data.1.cvp -p "your-password" -o /restore/dir

# 浏览卷内容（不还原）
CrypVol browse /output/dir/data.1.cvp

# 查看密钥元数据
CrypVol info /output/dir/data.1.cvk
```

### GUI 桌面应用

直接运行 `CrypVol`，在图形界面中拖拽文件或选择目录进行操作。

## 📖 加密模式

| 模式 | 说明 | 密钥存储 |
|------|------|----------|
| `None` | 数据明文或仅 GZip 压缩，不生成 `.cvk` | — |
| `PlainKey` | CEK 明文存储在 `.cvk` 中 | `.cvk` 文件即密钥 |
| `Password` | CEK 经 Argon2id + AES-GCM 加密 | 需要密码解密 `.cvk` |
| `Asymmetric` | CEK 经 RSA/ECC 公钥加密 | 需要对应私钥解密 `.cvk` |

### 文件格式

- **`.cvp`** — 加密数据卷文件，命名格式：`<前缀>.<卷号>.cvp`
- **`.cvk`** — 密钥文件，命名格式：`<前缀>.cvk`

## 🛠️ 技术栈

| 组件 | 技术 |
|------|------|
| 运行时 | .NET 10.0 |
| GUI 框架 | Avalonia UI 11.3 |
| MVVM | ReactiveUI + CommunityToolkit.Mvvm |
| CLI 框架 | System.CommandLine |
| 依赖注入 | Microsoft.Extensions.Hosting |
| 校验 | FluentValidation |

## 📁 项目结构

```
CrypVol.sln
├── CrypVol/              # 桌面应用入口
├── CrypVol.Core/          # 核心 GUI 逻辑 (ViewModels/Views)
├── CrypVol.Core.Abstract/ # 抽象层 (Services/Controls/ViewModels 接口)
├── CrypVol.Lib/           # 核心库 (加密/打包/解包逻辑)
└── CrypVol.Cli/           # 命令行工具
```

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！请先阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 📄 许可证

本项目采用 [GNU Lesser General Public License v2.1](LICENSE)。
