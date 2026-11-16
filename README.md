# CrypVol

[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![Avalonia](https://img.shields.io/badge/Avalonia-11.3-8B5CF6)](https://avaloniaui.net/)
[![License](https://img.shields.io/badge/license-LGPL--3.0-blue)](LICENSE)

CrypVol（Cryptographic Volume Package）是一个跨平台的加密分卷归档工具。它将文件流式拆为数据块，按需写入 `.cvp` 数据卷，并以
`.cvk` 保存或封装内容加密密钥（CEK）。提供命令行工具和 Avalonia 桌面应用。

项目的设计目标是可自举、可流式处理大文件，而不是追求严格等长的物理分卷：读取和恢复不依赖生成时指定的卷大小。

## 特性

- 流式分块读写：无需将大文件整体读入内存。
- 可拼接流水线：来源、独立处理器和接收端以有界 Channel 连接；支持压缩、加密、解密、解压等阶段组合。
- 多卷归档：文件可跨卷，输入任意一个卷即可自动发现同目录、同前缀的卷组。
- 密钥信封：支持明文 CEK、密码保护 CEK（Argon2id + AES-256-GCM）及 RSA 公钥接收者。
- 可编辑 CVK：可保留已有公钥接收者槽位，在没有原 PEM 文件时仍可重封装或删除接收者。
- 可恢复性工具：浏览、校验、修复、密钥重封装与块级重加密。
- 元数据与内容分离：CVK 负责密钥管理；引擎只接收轻量的 `CvkCredentials`（模式 + CEK）。

## 安装与构建

可从 [Releases](https://github.com/LeeQianXi/CrypVol/releases) 下载预编译版本，或从源码构建：

```bash
git clone https://github.com/LeeQianXi/CrypVol.git
cd CrypVol
dotnet build -c Release
```

本地发布 CLI 与 GUI：

```bash
bash scripts/publish-local.sh
```

默认输出为 `publish/local/linux-x64`。可传入目标目录与 RID：

```bash
bash scripts/publish-local.sh /opt/crypvol-publish linux-x64
```

开发环境需要 .NET SDK 10。CLI 项目为 `CrypVol.Cli`；构建后可通过 `dotnet run --project CrypVol.Cli -- <命令>` 使用。以下示例以已安装到
PATH 的 `crypvol` 表示。

```bash
crypvol --help
crypvol pack --help
```

## 概念

### CVP 数据卷

数据卷命名为 `<前缀>.<卷号>.cvp`。每个文件按数据块写入；当块跨越近似卷容量时，后续块会写入下一个卷，并由片段标志关联。卷头会标记数据是否压缩、是否加密和完整性等级。

`--volume-size` 是 **近似切分目标**，并非严格的文件大小上限。压缩后的长度、文件头和块边界都会使最终卷大小与该值略有差异；恢复、浏览和校验只解析卷内结构，不需要知道该参数。

`--chunk-size` 决定单次读取和处理的数据块大小（1–64 MiB，默认 16 MiB）：较大块通常有利于压缩率和吞吐，但会提高峰值内存。它也是调整大文件处理内存/性能平衡的主要开关。

### CVK 密钥文件

`.cvk` 是 Base64 编码的 CVK v3 容器，由固定 Header、明文 Metadata、密钥体（KeyBody）和 SHA-256 校验体组成。加载器先验证长度与校验体，再根据
Metadata 中的保护模式和算法自动选择解封路线。CVK 管理在引擎外由 `CvkDocument` 完成：加载后可修改保护模式、算法、密码、公钥接收者和元数据，再原子写入保存。

| 模式         | CEK 的保存方式                                               | 使用时所需凭据     |
|--------------|--------------------------------------------------------------|--------------------|
| `None`       | 不加密数据，也不生成 CVK                                     | 无                 |
| `PlainKey`   | CEK 写入明文密钥体                                           | CVK 文件本身       |
| `Password`   | 使用 Argon2id 派生密钥后，以 AES-256-GCM 封装 CEK            | CVK + 密码         |
| `Asymmetric` | 随机 DEK 由一个或多个公钥封装，DEK 再以 AES-256-GCM 封装 CEK | CVK + 任一匹配私钥 |

保护模式与算法是两个独立字段：`EncryptionMode` 只描述 CEK 如何被保护；`EncryptionAlgorithm` 描述公钥密钥体使用的算法（
`AesGcm` 或 `Ecc`，其中 `Ecc` 为 P-256 ECDH）。例如 ECC CVK 使用 `--mode Asymmetric --algorithm Ecc`，而不是把 ECC 当作一种保护模式。

`PlainKey` 仅适用于你能够安全存放 `.cvk` 文件的场景。密码、私钥和明文 CVK 都应视为敏感信息，不要提交到版本库或随数据卷一同公开分发。

## 快速开始

### 1. 打包

```bash
# 生成密码保护的 CVK，并打包目录
crypvol pack ./data -o ./archive --prefix backup \
  --mode Password --password "correct-horse-battery-staple"

# 生成 RSA 公钥保护的 CVK
crypvol pack ./data -o ./archive --prefix backup \
  --mode Asymmetric --public-key ./keys/alice.pem

# 使用已有 CVK；Password / Asymmetric CVK 需提供解封凭据
crypvol pack ./data -o ./archive --prefix backup \
  --key-file ./keys/backup.cvk --password "correct-horse-battery-staple"

# 流式块大小 32 MiB、近似卷目标 512 MiB、启用压缩
crypvol pack ./data -o ./archive --prefix backup \
  --chunk-size 32 --volume-size 512 --compression-level Optimal
```

未指定 `--key-file` 时，`pack` 按 `--mode` 创建新 CEK 和 CVK；指定 `--key-file` 时复用其中的 CEK，`--mode`、`--public-key` 和
`--comment` 不参与新 CVK 的创建。`--dry-run` 只根据原始大小和块大小给出近似卷数/块数，不写入数据或密钥文件。

### 2. 提取、浏览与校验

```bash
# 提取：提供任意一个卷即可自动发现卷组和同名 CVK
crypvol extract ./archive/backup.0.cvp -o ./restored \
  --password "correct-horse-battery-staple"

# 只提取匹配文件；默认遇到已存在文件会跳过
crypvol extract ./archive/backup.0.cvp -o ./restored \
  --include "**/*.pdf" --overwrite

# 不提取地浏览目录；可写出 Json/Csv/Table/List
crypvol browse ./archive/backup.0.cvp --format Json --output files.json

# 逐块校验；--quick 只检查头和结构
crypvol verify ./archive/backup.0.cvp --repair-report damage-report.txt
```

加密卷会自动尝试发现同目录、同前缀的 `.cvk`。若无法发现或需指定其他位置，请传入 `--key-file`；Password 模式配合 `--password`
。Asymmetric 模式会自动尝试当前用户 `~/.ssh` 中与同名 `.pub` 文件成对的私钥，也可用 `--privkey-key` 明确指定；加密私钥另可使用
`--key-pass`。

Asymmetric 模式仅使用 RSA：公钥支持 PEM 与 OpenSSH 的 `ssh-rsa` 单行格式；私钥支持 PKCS#1/PKCS#8
PEM、OpenSSH（含密码保护）、ssh.com 和 PuTTY PPK 格式。

### 3. 修复

```bash
# 基于校验报告定位损坏区域，先创建 .bak 备份
crypvol repair ./archive/backup.0.cvp -o ./repaired \
  --verify-report damage-report.txt --backup
```

修复会对无法恢复的损坏块进行零填充，并写入有效 CRC32 以维持卷结构；它不是原始数据恢复。请先备份并先用 `verify` 生成报告。

### 4. 管理与轮换密钥

```bash
# 单独创建 CVK
crypvol genkey --output ./keys --name backup --mode Password \
  --password "new-password"

# 查看并验证 CVK（密码或公钥模式须提供对应凭据）
crypvol info ./keys/backup.cvk --password "new-password"

# 重新封装同一个 CEK；保留注释与现有的 RSA 接收者槽位
crypvol rekey ./keys/backup.cvk --to-mode Password \
  --password "old-password" --new-password "better-password" --backup

# 变更为 RSA 模式，同时保留已存在接收者并增加一个新接收者
crypvol rekey ./keys/backup.cvk --to-mode Asymmetric \
  --password "better-password" --public-key ./keys/bob.pem

# 对卷中每个块重加密到一个已存在的目标 CVK
crypvol convert ./archive/backup.0.cvp \
  --old-key-file ./keys/old.cvk --old-password "old-password" \
  --key-file ./keys/new.cvk --password "new-password" \
  --output ./rotated --prefix backup-v2
```

`rekey` 改变的是 CVK 对 **同一 CEK**的保护方式，不会改写 `.cvp` 数据卷。它会先完成参数和构建校验；可选备份不会覆盖已有
`.bak`，写入使用同目录临时文件再替换目标。

`convert` 改变的是卷内数据块的加密密钥：使用旧 CEK 解密、使用新 CEK 加密。它 **只支持重加密到现有目标 CVK**，因此
`--key-file` 必须指定已有目标 CVK；该命令不会创建新的 CVK。

## 命令概览

| 命令      | 用途                                    |
|-----------|-----------------------------------------|
| `genkey`  | 创建独立的 CVK                          |
| `pack`    | 将文件或目录流式打包为 CVP 卷           |
| `extract` | 从卷组恢复文件                          |
| `browse`  | 不提取地列出卷内文件                    |
| `info`    | 加载并验证 CVK，显示保护模式和 CEK 指纹 |
| `verify`  | 校验卷结构和块级 CRC32，可生成修复报告  |
| `repair`  | 按报告或扫描结果对损坏块进行零填充修复  |
| `rekey`   | 修改既有 CVK 对同一 CEK 的保护方式      |
| `convert` | 使用既有目标 CVK 的 CEK 重加密数据卷    |

所有命令均支持 `--verbose` / `-v` 控制日志级别，例如 `-v Debug` 或 `-v Trace`。完整参数以运行时帮助为准：
`crypvol <command> --help`。

## 测试

单元测试与端到端 CLI 回归测试分别覆盖库行为和实际命令参数路径：

```bash
# xUnit 单元测试
dotnet test CrypVol.Tests/CrypVol.Tests.csproj

# Bash 端到端测试：自动构建 Release CLI；需要 Bash、.NET SDK 和 openssl
bash tests/run-tests.sh
```

脚本也可用 `CRYPVOL_BIN` 指向已发布的 CLI 可执行文件：`CRYPVOL_BIN=/path/to/CrypVol bash tests/run-tests.sh`。

## 处理引擎

核心引擎是一次性构建、构建后锁定的有界流水线：

```text
IDataProvider
    │ DataBlock（缓冲区 + BlockMetadata）
    ▼
Processor 1 ──► Processor 2 ──► … ──► IDataReceiver
```

- `IDataProvider`、`IDataProcessor`、`IDataReceiver` 均实现异步生命周期：初始化、校验、预处理、启动与释放。
- 每个阶段运行在独立任务中，阶段之间是容量为 1 的有界 `Channel<DataBlock>`。背压限制了内存占用，同时允许 I/O、压缩和加密并行推进。
- Provider、Processor 依次完成自己的下游 Channel；任一阶段失败或取消时，引擎关闭所有通道并取消所有阶段。
- 引擎事件为 `Starting`、`Started`、`Completed`、`Failed` 和 `Stopped`。处理器通过传入的 Engine 实例记录日志、报告异常或共享运行记录，而不是依赖额外
  Hook 接口。
- 当前内置组件包括 `SourceFileDataProvider`、`CvpFileDataProvider`、压缩/解压缩/加密/解密处理器，以及 `CvpFileReciver`、
  `DataFileReciver`。

## 格式与完整性

CVP 文件条目头使用 `CVPH`（明文）或 `CVPE`（加密）魔数；读取时自动识别，不需要人工指定卷的加密模式。加密数据块使用 AES-GCM，
`--integrity Block`（默认）会额外保存 CRC32，用于快速定位介质损坏。CRC32 用于损坏检测，不替代密码学认证；AES-GCM
的认证标签仍是加密数据的完整性保障。

## 项目结构

```text
CrypVol.sln
├── CrypVol/                 # Avalonia 桌面应用入口
├── CrypVol.Core/            # GUI 实现
├── CrypVol.Core.Abstract/   # GUI 抽象层
├── CrypVol.Cli/             # System.CommandLine 命令行工具
├── CrypVol.Lib/
│   ├── Crypto/              # CvkDocument、CvkLoader 与密钥信封
│   ├── Engine/              # Provider / Processor / Receiver 流水线
│   ├── Helper/              # Pack、Extract、Convert 等统一入口
│   ├── Volume/              # 卷发现、条目头与扫描
│   └── Utility/             # CRC32、Glob 等工具
└── CrypVol.Tests/           # xUnit 测试
```

## 许可证

[GNU Lesser General Public License v3.0](LICENSE)。
