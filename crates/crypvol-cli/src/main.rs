//! CrypVol 命令行入口。

use std::process::ExitCode;

use clap::{
    Arg, Command,
    builder::{PossibleValue, PossibleValuesParser},
};
use tracing_subscriber::filter::LevelFilter;

mod commands;
mod key;
mod migrate;

fn cli() -> Command {
    Command::new("crypvol")
        .version(env!("CARGO_PKG_VERSION"))
        .about("加密分卷归档工具")
        .arg_required_else_help(true)
        .subcommand_required(true)
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .short('v')
                .global(true)
                .help("启用日志；可使用 --verbose=LEVEL 指定级别")
                .value_name("LEVEL")
                .num_args(0..=1)
                .require_equals(true)
                .default_missing_value("Information")
                .ignore_case(true)
                .value_parser(PossibleValuesParser::new([
                    PossibleValue::new("Trace"),
                    PossibleValue::new("Debug"),
                    PossibleValue::new("Information").alias("Info"),
                    PossibleValue::new("Warning"),
                    PossibleValue::new("Error"),
                    PossibleValue::new("Critical"),
                    PossibleValue::new("None"),
                ])),
        )
        .subcommands(commands::all())
}

fn main() -> ExitCode {
    let matches = cli().get_matches();
    init_logging(matches.get_one::<String>("verbose").map(String::as_str));
    let (command, args) = matches.subcommand().expect("CLI requires a subcommand");
    tracing::info!(command, "开始执行命令");
    let result = match command {
        "info" => key::info(args),
        "genkey" => key::genkey(args),
        "rekey" => key::rekey(args),
        "migrate" => migrate::run(args),
        _ => Err(format!("`{command}` 尚未迁移到 Rust").into()),
    };
    match result {
        Ok(()) => {
            tracing::info!(command, "命令执行完成");
            ExitCode::SUCCESS
        }
        Err(error) => {
            tracing::debug!(command, error = %error, "命令执行失败");
            eprintln!("错误：{error}");
            ExitCode::FAILURE
        }
    }
}

fn init_logging(level: Option<&str>) {
    let level = match level {
        Some("Trace") => LevelFilter::TRACE,
        Some("Debug") => LevelFilter::DEBUG,
        Some("Information") | Some("Info") => LevelFilter::INFO,
        Some("Warning") => LevelFilter::WARN,
        Some("Error") | Some("Critical") => LevelFilter::ERROR,
        Some("None") => LevelFilter::OFF,
        None => LevelFilter::ERROR,
        Some(_) => unreachable!("clap validates the log level"),
    };
    let _ = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .without_time()
        .try_init();
}
