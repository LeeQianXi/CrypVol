# CrypVol — 加密分卷归档工具

[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![Avalonia](https://img.shields.io/badge/Avalonia-11.3-8B5CF6)](https://avaloniaui.net/)
[![License](https://img.shields.io/badge/license-LGPLv2.1-blue)](LICENSE)

**CrypVol**（Cryptographic Volume Package）是一个跨平台的加密分卷打包 / 还原工具，支持将任意文件或目录打包为带加密保护的 `.cvp` 数据卷，并提供配套的 `.cvk` 密钥文件管理。

## ✨ 特性

- 🔐 **多层加密支持** — PlainKey / 密码（Argon2id + AES-GCM）/ 非对称（RSA/ECC）三种模式
- 📦 **分卷存储** — 自动将大数据切分为指定大小的卷（`.cvp`），便于传输和存储
- 🗜️ **GZip 压缩** — 可选数据压缩，减少存储空间
- 🛡️ **完整性校验** — 可选的块级 CRC32 校验，检测磁盘静默损坏，支持校验和修复
- ⚡ **并行处理** — 多线程并行压缩 / 加密 / 校验，充分利用多核 CPU
- 🔄 **密钥轮换** — 支持在线重包装密钥信封（rekey）和块级密钥轮换（convert）
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

### 密钥管理

```bash
# 生成明文密钥
CrypVol genkey -o ./keys -n mykey

# 生成密码保护的密钥
CrypVol genkey -o ./keys -n mykey -m Password -p "your-password"

# 生成非对称密钥
CrypVol genkey -o ./keys -n mykey -m Asymmetric --public-key alice.pem
```

### 打包

```bash
# 基本打包（自动生成密钥）
CrypVol pack /path/to/data -m Password -p "your-password" -o /output

# 复用已有密钥
CrypVol pack /path/to/data --key-file ./keys/mykey.cvk -p "your-password" -o /output

# 压缩 + 分卷 (512MB) + 完整性校验
CrypVol pack /path/to/data -m Password -p "your-password" -s 512 -c --integrity Block

# 仅包含特定文件类型，预览不写入
CrypVol pack /path/to/data --include "**/*.jpg" --dry-run
```

### 还原

```bash
# 用密码还原
CrypVol extract ./output/data.1.cvp -p "your-password" -o /restore

# 用私钥还原（非对称模式）
CrypVol extract ./output/data.1.cvp --privkey-key ./alice.key -o /restore

# 过滤 + 覆盖已存在文件
CrypVol extract ./output/data.1.cvp --include "**/*.docx" -o /restore --overwrite
```

### 浏览

```bash
# 列出卷内文件
CrypVol browse ./output/data.1.cvp

# 长格式（含文件大小、跨卷分段）
CrypVol browse ./output/data.1.cvp -l

# 过滤
CrypVol browse ./output/data.1.cvp --include "**/*.jpg"
```

### 校验 & 修复

```bash
# 校验卷完整性
CrypVol verify ./output/data.1.cvp

# 快速模式（仅检查卷头结构）
CrypVol verify ./output/data.1.cvp --quick

# 生成损坏报告
CrypVol verify ./output/data.1.cvp --repair-report damage.txt

# 扫描并修复损坏块（零填充 + 有效 CRC32）
CrypVol repair ./output/data.1.cvp -k ./keys/mykey.cvk -o ./fixed

# 从损坏报告精确修复（跳过扫描）
CrypVol repair ./output/data.1.cvp -k ./keys/mykey.cvk -o ./fixed --verify-report damage.txt

# 修复前创建 .bak 备份
CrypVol repair ./output/data.1.cvp -k ./keys/mykey.cvk -o ./fixed --backup
```

### 密钥操作

```bash
# 查看密钥元数据
CrypVol info ./keys/mykey.cvk

# 查看密码保护的密钥（提供密码可看到 CEK 指纹）
CrypVol info ./keys/mykey.cvk -p "your-password"

# 重包装密钥信封（CEK 不变，更换保护方式）
CrypVol rekey ./keys/mykey.cvk --to-mode Password --new-password "better-password" -b

# 块级密钥轮换（.A 用旧 CEK 解 → 新 CEK 加密）
CrypVol convert ./output/data.1.cvp -k ./keys/old.cvk -p "oldpass" \
    --key-file ./keys/new.cvk -o ./converted
```

## 📖 加密模式

| 模式 | 说明 | 密钥存储 |
|------|------|----------|
| `None` | 数据明文或仅 GZip 压缩，不生成 `.cvk` | — |
| `PlainKey` | CEK 明文存储在 `.cvk` 中 | `.cvk` 文件即密钥 |
| `Password` | CEK 经 Argon2id + AES-GCM 加密 | 需要密码解密 `.cvk` |
| `Asymmetric` | CEK 经 RSA/ECC 公钥加密 | 需要对应私钥解密 `.cvk` |

## 🛡️ 完整性校验

| 级别 | 说明 | 开销 |
|------|------|------|
| `None` | 不嵌入校验数据 | 0 |
| `Block` | 每个数据块附带 CRC32 校验值 | +4 字节 / 块 (~0.1%) |
| `File` | 块级 + 每个文件附带 SHA256 | 预留（暂未实现） |
| `Volume` | 上述全部 + 卷末尾附带整卷 SHA256 | 预留（暂未实现） |

CRC32 校验值嵌入在加密数据块末尾，打包时自动计算，提取时自动验证。卷损坏时 `verify` 可精确定位损坏块，`repair` 可零填充损坏块以保留卷结构完整性。

## 📁 文件格式

- **`.cvp`** — 加密数据卷文件，命名格式：`<前缀>.<卷号>.cvp`
- **`.cvk`** — 密钥文件，命名格式：`<前缀>.cvk`

### .cvp 卷结构

```
[FileEntryHeader]              ← 256B (plain) 或 284B (AES-GCM 加密)
  ├── Magic (0x48505643)
  ├── FileId (FNV-1a-64 路径哈希)
  ├── Flags (bits 0-1: 段类型, bit 2: 扩展头, bits 3-4: IntegrityLevel)
  ├── FragmentIndex
  ├── SizeOrTotal
  └── FilePath (UTF-8, 最多 231 字节)

[int32 BlockLen] [BlockData]   ← 数据块 = Nonce(12) + Ciphertext + Tag(16) + [CRC32(4)]
[int32 BlockLen] [BlockData]
...
```

### .cvk 密钥文件结构

```
[Magic "KEY0"] [Version=1] [Mode] [PayloadLength] [Payload...] → Base64 编码
```

## 🛠️ 技术栈

| 组件 | 技术 |
|------|------|
| 运行时 | .NET 10.0 |
| GUI 框架 | Avalonia UI 11.3 |
| MVVM | ReactiveUI + CommunityToolkit.Mvvm |
| CLI 框架 | System.CommandLine |
| 依赖注入 | Microsoft.Extensions.Hosting |
| 加密 | AES-256-GCM + Argon2id + RSA/ECC |
| CRC32 | IEEE 802.3 (自定义实现) |

## 📁 项目结构

```
CrypVol.sln
├── CrypVol/                 # 桌面应用入口
├── CrypVol.Core/            # 核心 GUI 逻辑 (ViewModels/Views)
├── CrypVol.Core.Abstract/   # 抽象层 (Services/Controls/ViewModels 接口)
├── CrypVol.Lib/             # 核心库
│   ├── Crypto/              # CVK 密钥信封读写
│   ├── Volume/              # 卷发现/分配/扫描
│   ├── Engine/              # 核心引擎 (Pack/Extract/Browse/Convert/Verify/Repair)
│   │   └── Models/          # 选项/结果记录
│   ├── Pipeline/            # 并行流水线 (Channel-based)
│   ├── Transforms/          # 块变换 (加密/解密/压缩/CRC32)
│   ├── IO/                  # 数据源/汇
│   │   ├── Sources/         # FileSource, CvpSource
│   │   └── Sinks/           # FileSink, CvpSink
│   ├── Extensions/          # LINQ 扩展
│   └── Utility/             # 引用池/单例工具
├── CrypVol.Cli/             # 命令行工具
└── CrypVol.Tests/           # 测试 (181 xUnit + 72 bash)
```

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！请先阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 📄 许可证

本项目采用 [GNU Lesser General Public License v2.1](LICENSE)。
