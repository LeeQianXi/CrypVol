//! 命令参数与帮助文本。

use std::path::PathBuf;

mod key;

use clap::{
    Arg, ArgAction, Command,
    builder::{PathBufValueParser, TypedValueParser},
    value_parser,
};

pub fn all() -> [Command; 10] {
    [
        pack(),
        volumes("extract", "从数据卷恢复文件")
            .arg(output("目标还原目录", "DIR"))
            .args(credentials())
            .args(filters())
            .arg(flag("overwrite", "覆盖已有文件")),
        volumes("browse", "列出卷内文件")
            .arg(output("列表输出文件，默认写入标准输出", "FILE"))
            .arg(
                choice("format", "列表格式", ["List", "Table", "Json", "Csv"])
                    .short('f')
                    .default_value("List"),
            )
            .arg(flag("long", "显示详细文件信息").short('l'))
            .args(credentials())
            .args(filters()),
        volumes("verify", "校验数据卷完整性")
            .args(credentials())
            .args(filters())
            .arg(flag("quick", "仅执行快速校验"))
            .arg(path("repair-report", "写入损坏报告", "FILE").short('r')),
        volumes("repair", "修复损坏的数据卷")
            .arg(output("修复卷输出目录", "DIR"))
            .args(credentials())
            .arg(
                path("verify-report", "读取 verify 生成的损坏报告", "FILE")
                    .value_parser(PathBufValueParser::new().try_map(input_file)),
            )
            .arg(flag("backup", "备份原始卷").short('b')),
        convert(),
        key::genkey(),
        key::info(),
        key::rekey(),
        key::migrate(),
    ]
}

fn pack() -> Command {
    Command::new("pack")
        .about("将文件或目录打包为 CVP 数据卷")
        .arg(
            Arg::new("source")
                .value_name("PATH")
                .help("源文件或目录")
                .required(true)
                .value_parser(PathBufValueParser::new().try_map(existing_path)),
        )
        .arg(output("数据卷输出目录", "DIR"))
        .arg(prefix())
        .next_help_heading("密钥")
        .args(credentials())
        .arg(mode("mode").short('m').default_value("Plain"))
        .arg(algorithm())
        .arg(public_keys())
        .arg(path(
            "key-output",
            "新密钥输出目录，默认与数据卷相同",
            "DIR",
        ))
        .arg(comment())
        .next_help_heading("数据处理")
        .arg(
            option("volume-size", "近似分卷大小（MiB）", "MIB")
                .short('s')
                .default_value("1024")
                .value_parser(value_parser!(u32).range(1..)),
        )
        .arg(
            option("chunk-size", "分块大小（MiB）", "MIB")
                .default_value("16")
                .value_parser(value_parser!(u32).range(1..=64)),
        )
        .arg(flag("no-compress", "禁用压缩"))
        .arg(
            choice(
                "compression-level",
                "GZip 压缩预设",
                ["Fastest", "Optimal", "SmallestSize", "NoCompression"],
            )
            .default_value("Optimal"),
        )
        .arg(
            choice(
                "integrity",
                "完整性级别",
                ["None", "Block", "File", "Volume"],
            )
            .default_value("Block"),
        )
        .args(filters())
        .arg(flag("dry-run", "预估卷数和块数"))
}

fn convert() -> Command {
    volumes("convert", "使用目标 CVK 的密钥重加密数据卷")
        .arg(output("新卷输出目录", "DIR"))
        .arg(prefix().default_value("converted"))
        .arg(flag("backup", "备份原始卷").short('b'))
        .next_help_heading("源密钥")
        .arg(key_file("old-key-file", "源 CVK 文件").short('k'))
        .arg(option("old-password", "源 CVK 密码", "PASSPHRASE"))
        .arg(private_key("old-privkey-key", "源 CVK 的解封私钥"))
        .arg(option("old-key-pass", "源私钥密码", "PASSPHRASE"))
        .next_help_heading("目标密钥")
        .arg(key_file("key-file", "目标 CVK 文件").required(true))
        .args(unlock())
}

fn volumes(name: &'static str, about: &'static str) -> Command {
    Command::new(name).about(about).arg(
        Arg::new("volumes")
            .value_name("CVP")
            .help("一个或多个数据卷路径")
            .required(true)
            .num_args(1..)
            .value_parser(PathBufValueParser::new().try_map(input_file)),
    )
}

fn credentials() -> [Arg; 4] {
    let [password, key, passphrase] = unlock();
    [
        key_file("key-file", "使用已有 CVK 文件").short('k'),
        password,
        key,
        passphrase,
    ]
}

fn unlock() -> [Arg; 3] {
    [
        password(),
        private_key("privkey-key", "解封 CVK 的私钥"),
        option("key-pass", "私钥文件密码", "PASSPHRASE"),
    ]
}

fn password() -> Arg {
    option("password", "CVK 密码", "PASSPHRASE").short('p')
}

fn filters() -> [Arg; 2] {
    [
        option("include", "包含匹配的路径", "GLOB"),
        option("exclude", "排除匹配的路径", "GLOB"),
    ]
}

fn mode(name: &'static str) -> Arg {
    choice(name, "CVK 保护方式", ["Plain", "Password", "PublicKey"])
}

fn algorithm() -> Arg {
    choice(
        "algorithm",
        "CVK 封装算法",
        [
            "None",
            "PasswordPbkdf2Sha256",
            "PasswordArgon2Id",
            "RsaOaepSha256",
            "RsaOaepSha384",
            "RsaOaepSha512",
            "EcdhP256",
            "EcdhP384",
            "EcdhP521",
        ],
    )
}

fn public_keys() -> Arg {
    path("public-key", "接收者公钥文件，可重复", "FILE")
        .value_parser(PathBufValueParser::new().try_map(input_file))
        .action(ArgAction::Append)
}

fn key_file(name: &'static str, help: &'static str) -> Arg {
    path(name, help, "CVK").value_parser(PathBufValueParser::new().try_map(input_file))
}

pub(super) fn private_key(name: &'static str, help: &'static str) -> Arg {
    path(name, help, "FILE").value_parser(PathBufValueParser::new().try_map(input_file))
}

fn output(help: &'static str, value: &'static str) -> Arg {
    path("output", help, value).short('o')
}

fn prefix() -> Arg {
    option("output-prefix", "输出文件名前缀", "NAME").visible_alias("prefix")
}

fn comment() -> Arg {
    option("comment", "CVK 注释", "TEXT")
}

fn option(name: &'static str, help: &'static str, value: &'static str) -> Arg {
    Arg::new(name).long(name).help(help).value_name(value)
}

fn flag(name: &'static str, help: &'static str) -> Arg {
    Arg::new(name)
        .long(name)
        .help(help)
        .action(ArgAction::SetTrue)
}

fn path(name: &'static str, help: &'static str, value: &'static str) -> Arg {
    option(name, help, value).value_parser(value_parser!(PathBuf))
}

fn choice<const N: usize>(
    name: &'static str,
    help: &'static str,
    values: [&'static str; N],
) -> Arg {
    option(name, help, "VALUE")
        .value_parser(values)
        .ignore_case(true)
}

fn existing_path(path: PathBuf) -> Result<PathBuf, &'static str> {
    if path.exists() {
        Ok(path)
    } else {
        Err("路径不存在或不可访问")
    }
}

fn input_file(path: PathBuf) -> Result<PathBuf, &'static str> {
    if path.is_file() {
        Ok(path)
    } else {
        Err("需要可访问的普通文件")
    }
}
