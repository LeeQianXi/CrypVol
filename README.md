# CrypVol

CrypVol 是一个以 Rust 实现的加密分卷归档项目。当前版本重点完成 CVK 密钥信封的创建、验证、重封装和旧格式迁移，并提供 CVP 记录格式解析。

## 当前状态

已可用：

- `genkey`：创建 CVK。
- `info`：校验并查看 CVK。
- `rekey`：重封装同一 CEK、维护接收者和元数据。
- `migrate`：将旧版 CVK 转为原生 CVK。
- `crypvol-core`：CVK1 读写、密码与公钥保护、PEM/OpenSSH 密钥读取、CVP 记录解析。
- `crypvol-gui`：原生文件对话框、CVK 加载与验证、Header 元数据编辑、公钥接收者维护及原子保存。

`pack`、`extract`、`browse`、`verify`、`repair` 与 `convert` 已有命令帮助，但尚未迁移到 Rust 处理器；调用时会明确失败，不能用于生产数据。

## 构建

需要 Rust `1.100` 或更新版本，以及构建 vendored OpenSSL 所需的本机 C 工具链和 Perl。

```bash
git clone https://github.com/LeeQianXi/CrypVol.git
cd CrypVol
cargo build --workspace --release
```

运行 CLI：

```bash
cargo run -p crypvol-cli -- --help
cargo run -p crypvol-cli -- genkey --help
```

## CVK 密钥信封

CVK 文件以 `CVK1` 为魔数，包含长度前缀、UTF-8 JSON Header、密钥体和 SHA-256 完整性摘要。Header 参与受保护密钥体的认证；密码或私钥错误时不会使用解封结果。

| 保护方式 | 可用封装算法 | 所需凭据 |
|---|---|---|
| `Plain` | `None` | CVK 文件 |
| `Password` | `PasswordPbkdf2Sha256`、`PasswordArgon2Id` | CVK 密码 |
| `PublicKey` | RSA-OAEP-SHA-256/384/512、ECDH P-256/384/521 | 匹配的私钥 |

`Plain` CVK 包含明文 CEK，只应在可安全保管文件的场景使用。密码、私钥、CEK 与明文 CVK 都不应写入版本库、日志或命令历史。

## 常用操作

创建密码保护 CVK：

```bash
cargo run -p crypvol-cli -- genkey \
  --output ./keys --name archive \
  --mode Password --password 'correct-horse-battery-staple'
```

创建公钥保护 CVK：

```bash
cargo run -p crypvol-cli -- genkey \
  --output ./keys --name archive \
  --mode PublicKey --algorithm RsaOaepSha256 \
  --public-key ./keys/alice.pub
```

查看并验证 CVK：

```bash
cargo run -p crypvol-cli -- info ./keys/archive.cvk --password 'correct-horse-battery-staple'
cargo run -p crypvol-cli -- info ./keys/archive.cvk --privkey-key ./keys/alice.pem
```

重封装不会改变 CEK。`rekey` 默认创建源文件的 `.bak` 备份；使用 `--backup=false` 可禁用备份。

```bash
cargo run -p crypvol-cli -- rekey ./keys/archive.cvk \
  --password 'old-password' \
  --to-mode Password --new-password 'new-password' \
  --label archive-2026
```

迁移始终写入新文件，不会覆盖源 CVK：

```bash
cargo run -p crypvol-cli -- migrate ./keys/legacy.cvk \
  --output ./keys/archive.cvk --password 'password'
```

运行 `crypvol-cli <command> --help` 获取完整参数。`-v` 或 `--verbose=Debug` 可启用 CLI 与核心库的结构化阶段日志；日志不会输出密码、私钥或 CEK。

## 项目结构

```text
crates/
├── crypvol-core/  # CVK 密码学、格式与 CVP 记录解析
├── crypvol-cli/   # clap 命令定义、分发与 CVK 工作流
├── crypvol-gui/   # Iced 多窗口 CVK 编辑流水线
└── crypvol-migrate/ # 旧版 CVK 的独立兼容层
```

## 验证

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release
```

## 许可证

[GNU Lesser General Public License v3.0](LICENSE)
