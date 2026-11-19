use clap::{
    Arg, ArgAction, Command,
    builder::{PathBufValueParser, TypedValueParser},
    value_parser,
};

use super::{
    algorithm, comment, flag, input_file, mode, option, output, password, private_key, public_keys,
    unlock,
};

pub(super) fn genkey() -> Command {
    Command::new("genkey")
        .about("创建独立的 CVK 密钥文件")
        .arg(output("密钥输出目录", "DIR").default_value("."))
        .arg(
            option("name", "密钥文件名（不含扩展名）", "NAME")
                .short('n')
                .default_value("key"),
        )
        .arg(mode("mode").short('m').default_value("Plain"))
        .arg(algorithm())
        .arg(password())
        .arg(public_keys())
        .arg(comment())
        .arg(option("cek", "指定密钥材料（64 个十六进制字符）", "HEX"))
}

pub(super) fn info() -> Command {
    Command::new("info")
        .about("查看 CVK 密钥文件信息")
        .arg(cvk())
        .args(unlock())
}

pub(super) fn rekey() -> Command {
    Command::new("rekey")
        .about("重新封装 CVK 或修改接收者和元数据")
        .arg(cvk())
        .arg(output("新 CVK 输出路径，默认使用源路径", "FILE"))
        .arg(
            option("backup", "是否备份原始 CVK", "BOOL")
                .short('b')
                .num_args(0..=1)
                .default_missing_value("true")
                .default_value("true")
                .value_parser(value_parser!(bool)),
        )
        .next_help_heading("当前密钥")
        .args(unlock())
        .next_help_heading("新封装与接收者")
        .arg(mode("to-mode"))
        .arg(algorithm())
        .arg(option("new-password", "新 CVK 密码", "PASSPHRASE"))
        .arg(public_keys())
        .arg(
            option("remove-public-key", "按 KeyId 移除接收者，可重复", "ID")
                .action(ArgAction::Append),
        )
        .arg(flag("clear-public-keys", "清空现有接收者"))
        .next_help_heading("元数据")
        .arg(option("label", "CVK 标签", "TEXT"))
        .arg(flag("clear-label", "清除 CVK 标签"))
        .arg(option("description", "CVK 描述", "TEXT"))
        .arg(flag("clear-description", "清除 CVK 描述"))
        .arg(comment())
        .arg(flag("clear-comment", "清除 CVK 注释"))
}

pub(super) fn migrate() -> Command {
    Command::new("migrate")
        .about("将旧版 CVK 迁移为 Rust 原生 CVK")
        .arg(cvk())
        .arg(output("迁移后的原生 CVK 路径", "FILE").required(true))
        .next_help_heading("旧密钥")
        .args(migration_credentials())
}

fn migration_credentials() -> [Arg; 3] {
    [
        password().help("旧 CVK 的密码"),
        private_key("privkey-key", "旧 CVK 的解封私钥"),
        option("key-pass", "旧私钥文件密码", "PASSPHRASE"),
    ]
}

fn cvk() -> Arg {
    Arg::new("cvk")
        .value_name("CVK")
        .help("密钥文件路径")
        .required(true)
        .value_parser(PathBufValueParser::new().try_map(input_file))
}
