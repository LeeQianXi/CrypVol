//! CVK 命令的端到端和互操作测试。

#[path = "cvk/concurrency.rs"]
mod concurrency;
#[path = "cvk/key_files.rs"]
mod key_files;
#[path = "cvk/key_formats.rs"]
mod key_formats;
#[path = "cvk/lifecycle.rs"]
mod lifecycle;
#[path = "cvk/migrate.rs"]
mod migrate;
#[path = "cvk/password.rs"]
mod password;
#[path = "cvk/public_key.rs"]
mod public_key;
#[path = "cvk/support.rs"]
mod support;
#[path = "cvk/transitions.rs"]
mod transitions;
#[path = "cvk/validation.rs"]
mod validation;
