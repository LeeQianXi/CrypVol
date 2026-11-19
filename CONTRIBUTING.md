# 贡献指南

欢迎改进 CrypVol。提交前请以仓库当前 Rust 实现和测试为准，不依据尚未实现的命令帮助推断功能已经可用。

## 开发环境

- Rust `1.100` 或更新版本。
- Windows、macOS 或 Linux。
- 构建 vendored OpenSSL 所需的本机 C 工具链和 Perl。

```bash
git clone https://github.com/LeeQianXi/CrypVol.git
cd CrypVol
cargo build --workspace
cargo run -p crypvol-cli -- --help
```

## 代码约定

- 遵循 Rust API Guidelines 与 `rustfmt` 的默认格式。
- `crypvol-core` 放置格式、密码学、卷处理与无界面业务逻辑；CLI 不复制核心逻辑。
- 命令参数定义、校验和处理应按命令组织；通用入口只负责解析、分发与退出状态。
- 外部输入、文件操作和密码学操作应返回可理解的 `Result`。除内部不变量外，不使用 `unwrap` 或 `expect`。
- 不在错误、日志、测试输出或提交内容中暴露密码、私钥、CEK 或明文敏感数据。
- 新增依赖、公共接口或格式变更时，说明用途、许可证、兼容性和测试覆盖。

## 提交前检查

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release
git diff --check
```

涉及 CVK 格式、密码学参数或兼容读取时，请补充格式边界、认证失败和跨实现样本测试。

## 提交信息

推荐使用 Conventional Commits：

- `feat:` 新功能
- `fix:` 缺陷修复
- `docs:` 文档
- `refactor:` 重构
- `test:` 测试
- `chore:` 构建或工具

## 报告问题

请在 Issue 中提供：

- 可复现步骤和实际输出。
- 期望行为。
- 操作系统、Rust 工具链版本和命令行参数。
- 对密钥或 CVK 问题，提供经过脱敏的最小样本；不要上传真实凭据。
