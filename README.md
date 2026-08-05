# CrypVol — 加密分卷归档工具

[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![Avalonia](https://img.shields.io/badge/Avalonia-11.3-8B5CF6)](https://avaloniaui.net/)
[![License](https://img.shields.io/badge/license-LGPLv2.1-blue)](LICENSE)

**CrypVol**（Cryptographic Volume Package）是一个跨平台的加密分卷打包/还原工具，核心能力是将文件加密后切分为指定大小的 `.cvp` 数据卷，配合 `.cvk` 密钥文件实现多层密钥保护。

## ✨ 特性

- 🔐 **多层加密** — PlainKey / 密码（Argon2id + AES-GCM）/ 非对称（RSA/ECC）
- 📦 **分卷存储** — 自动切分为指定大小（`.cvp`），支持跨卷文件
- 🛡️ **完整性校验** — 块级 CRC32，`verify` 定位 + `repair` 零填充修复
- ⚡ **并行流水线** — Channel-based 多线程并发，充分利用多核
- 🔄 **密钥轮换** — Rekey（重包装密钥信封）+ Convert（块级 CEK 轮换）
- 🔍 **元数据浏览** — 不还原即可浏览卷内文件，支持 Table/Json/Csv 输出
- 🪄 **自描述格式** — CVPH（明文）/ CVPE（加密）双魔数，无需手动指定加密模式
- 🖥️ **GUI + CLI** — Avalonia 跨平台桌面 + System.CommandLine 命令行

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
crypvol genkey -o ./keys -n mykey

# 生成密码保护的密钥
crypvol genkey -o ./keys -n mykey -m Password -p "your-password"

# 生成非对称密钥
crypvol genkey -o ./keys -n mykey -m Asymmetric --public-key alice.pem
```

### 打包

```bash
# 基本打包（自动生成密钥）
crypvol pack /path/to/data -m Password -p "your-password" -o /output

# 复用已有密钥
crypvol pack /path/to/data --key-file ./keys/mykey.cvk -p "your-password" -o /output

# 分卷 512MB + 块级完整性校验
crypvol pack /path/to/data -m Password -p "your-password" -s 512 --integrity Block

# 仅包含特定文件类型（预览）
crypvol pack /path/to/data --include "**/*.jpg" --dry-run
```

### 还原

```bash
# 用密码还原（.cvk 自动发现）
crypvol extract ./output/data.1.cvp -p "your-password" -o /restore

# 用私钥还原（非对称模式）
crypvol extract ./output/data.1.cvp --privkey-key ./alice.key -o /restore

# 过滤 + 覆盖
crypvol extract ./output/data.1.cvp --include "**/*.docx" -o /restore --overwrite
```

### 浏览

```bash
# 表格格式（默认）
crypvol browse ./output/data.1.cvp

# JSON 输出到文件
crypvol browse ./output/data.1.cvp -f Json -o filelist.json

# CSV + 长格式（含跨卷链）
crypvol browse ./output/data.1.cvp -f Csv -l

# 简洁列表 + 过滤
crypvol browse ./output/data.1.cvp -f List --include "**/*.jpg"
```

### 校验 & 修复

```bash
# 校验卷完整性
crypvol verify ./output/data.1.cvp

# 快速模式
crypvol verify ./output/data.1.cvp --quick

# 生成损坏报告
crypvol verify ./output/data.1.cvp --repair-report damage.txt

# 修复（零填充损坏块 + 有效 CRC32）
crypvol repair ./output/data.1.cvp -k ./keys/mykey.cvk -o ./fixed

# 从报告修复 + 备份
crypvol repair ./output/data.1.cvp -k ./keys/mykey.cvk -o ./fixed \
    --verify-report damage.txt --backup
```

### 密钥操作

```bash
# 查看密钥元数据
crypvol info ./keys/mykey.cvk

# 重包装密钥信封
crypvol rekey ./keys/mykey.cvk --to-mode Password --new-password "better-password"

# 块级密钥轮换
crypvol convert ./output/data.1.cvp -k ./keys/old.cvk -p "oldpass" \
    --key-file ./keys/new.cvk -o ./converted
```

## 📖 加密模式

| 模式 | 说明 | 密钥存储 |
|------|------|----------|
| `None` | 数据明文，不生成 `.cvk` | — |
| `PlainKey` | CEK 明文存储在 `.cvk` 中 | `.cvk` 文件即密钥 |
| `Password` | CEK 经 Argon2id + AES-GCM 加密 | 需要密码解密 `.cvk` |
| `Asymmetric` | CEK 经 RSA/ECC 公钥加密 | 需要对应私钥解密 `.cvk` |

## 🛡️ 完整性校验

| 级别 | 说明 | 开销 |
|------|------|------|
| `None` | 不嵌入校验数据 | 0 |
| `Block` | 每个数据块附带 CRC32 | +4 字节/块 |

## 📁 文件格式

- **`.cvp`** — 数据卷文件：`<前缀>.<卷号>.cvp`
- **`.cvk`** — 密钥文件：`<前缀>.cvk`（Base64 编码）

### .cvp 卷结构

```
[FileEntryHeader]               ← 256B 明文 (CVPH) 或 284B 加密 (CVPE)
  ├── Magic: 0x48505643 "CVPH" (明文) / 0x45505643 "CVPE" (加密)
  ├── FileId (FNV-1a-64 路径哈希)
  ├── Flags (bits 0-1: Full/CrossHead/CrossMid/CrossTail, bit 2: 扩展头, bits 3-4: Integrity)
  ├── FragmentIndex
  ├── SizeOrTotal
  └── FilePath (UTF-8, 最多 231 字节)

[int32 BlockLen] [BlockData]    ← Nonce(12) + Ciphertext + Tag(16) + [CRC32(4)]
[int32 BlockLen] [BlockData]
...
```

魔数 `CVPH` = 明文头，`CVPE` = 加密头。两者均为明文存放，扫描时自动识别，**无需手动指定加密模式**。

加密只覆盖头部 Magic 之后的 252 字节。数据块始终为明文长度前缀 + Nonce/Ciphertext/Tag 结构。

### .cvk 密钥文件结构

```
[Magic "KEY0"] [Version=1] [Mode] [PayloadLength] [Payload...] → Base64
```

## 🛠️ 技术栈

| 组件 | 技术 |
|------|------|
| 运行时 | .NET 10.0 |
| GUI | Avalonia UI 11.3 |
| CLI | System.CommandLine |
| 加密 | AES-256-GCM + Argon2id + RSA/ECC |
| 哈希 | FNV-1a-64 (FileId), CRC32 (IEEE 802.3) |

## 📁 项目结构

```
CrypVol.sln
├── CrypVol/                 # 桌面应用入口
├── CrypVol.Core/            # GUI (ViewModels/Views)
├── CrypVol.Core.Abstract/   # 抽象层
├── CrypVol.Lib/             # 核心库
│   ├── Crypto/              # .cvk 密钥信封读写
│   ├── Volume/              # 卷发现/分配/扫描
│   ├── Engine/              # 核心引擎 (Pack/Extract/Browse/Convert/Verify/Repair)
│   │   └── Models/          # 选项/结果记录
│   ├── Pipeline/            # Channel-based 并行流水线
│   ├── Transforms/          # 块变换 (加密/解密/压缩/CRC32)
│   ├── IO/                  # 数据源/汇
│   │   ├── Sources/         # FileSource, CvpSource
│   │   └── Sinks/           # FileSink, CvpSink
│   └── Extensions/
├── CrypVol.Cli/             # 命令行工具
└── CrypVol.Tests/           # 测试 (181 xUnit)
```

## 📄 许可证

LGPL v2.1 — 详见 [LICENSE](LICENSE)。
