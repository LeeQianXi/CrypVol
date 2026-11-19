use std::path::PathBuf;

use crypvol_core::crypto::{CvkEnvelope, CvkHeader, KeyProtection, KeyWrapAlgorithm, encode};
use zeroize::Zeroizing;

use super::{
    Result, add_public_keys, algorithm, protection, read_cvk_file, read_public_keys, storage,
    unlock_for_command, validate_recipients,
};

pub fn rekey(args: &clap::ArgMatches) -> Result<()> {
    let source = args.get_one::<PathBuf>("cvk").unwrap();
    let locked_source = storage::lock_source(source)?;
    let data = read_cvk_file(&locked_source)?;
    let envelope = CvkEnvelope::parse(&data)?;
    let old = envelope.header();
    let mode = match args.get_one::<String>("to-mode") {
        Some(value) => protection(value)?,
        None => old.key_protection,
    };
    let alg = validate_options(args, old, mode)?;
    let added_recipients = read_public_keys(args)?;
    let mut payload = unlock_for_command(&envelope, args)?;
    if args.get_flag("clear-public-keys") {
        payload.recipient_keys.clear();
    }
    if let Some(ids) = args.get_many::<String>("remove-public-key") {
        for id in ids {
            let original_len = payload.recipient_keys.len();
            payload
                .recipient_keys
                .retain(|recipient| recipient.key_id != *id);
            if payload.recipient_keys.len() == original_len {
                return Err(format!("未找到接收者：{id}").into());
            }
        }
    }
    add_public_keys(&mut payload, added_recipients)?;
    validate_recipients(mode, alg, &payload.recipient_keys)?;
    let new_password = args
        .get_one::<String>("new-password")
        .map(String::as_str)
        .or_else(|| {
            if mode == old.key_protection {
                args.get_one::<String>("password").map(String::as_str)
            } else {
                None
            }
        });
    let header = CvkHeader {
        version: old.version,
        key_protection: mode,
        key_wrap_algorithm: alg,
        label: metadata(args, "label", "clear-label", &old.label)?,
        description: metadata(args, "description", "clear-description", &old.description)?,
        comment: metadata(args, "comment", "clear-comment", &old.comment)?,
        created_at: old.created_at.clone(),
        generator: old.generator.clone(),
    };
    let encoded = Zeroizing::new(encode(&header, &payload, new_password)?);
    let output = args.get_one::<PathBuf>("output").unwrap_or(source);
    if *args.get_one::<bool>("backup").unwrap() {
        let mut backup = source.as_os_str().to_os_string();
        backup.push(".bak");
        let backup_path = PathBuf::from(backup);
        if *output == backup_path {
            return Err("输出文件不能与备份文件相同".into());
        }
        storage::create(&backup_path, &data)?;
        if output.exists() && same_file::is_same_file(output, &backup_path)? {
            return Err("输出文件不能与备份文件相同".into());
        }
    }
    storage::replace(output, &encoded)?;
    println!("已写入 {}", output.display());
    Ok(())
}

fn validate_options(
    args: &clap::ArgMatches,
    old: &CvkHeader,
    mode: KeyProtection,
) -> Result<KeyWrapAlgorithm> {
    let changes_recipients = args.contains_id("public-key")
        || args.contains_id("remove-public-key")
        || args.get_flag("clear-public-keys");
    if mode != KeyProtection::PublicKey && changes_recipients {
        return Err("接收者选项需要公钥保护模式".into());
    }
    if mode != KeyProtection::Password && args.contains_id("new-password") {
        return Err("只有密码保护模式可以使用 --new-password".into());
    }
    if mode == KeyProtection::Password {
        let password = args.get_one::<String>("new-password").or_else(|| {
            (mode == old.key_protection)
                .then(|| args.get_one::<String>("password"))
                .flatten()
        });
        if password.is_none_or(|value| value.trim().is_empty()) {
            return Err("密码保护模式需要非空密码".into());
        }
    }
    let algorithm = if args.contains_id("algorithm") || args.contains_id("to-mode") {
        algorithm(mode, args.get_one::<String>("algorithm"))?
    } else {
        old.key_wrap_algorithm
    };
    for (value, clear) in [
        ("label", "clear-label"),
        ("description", "clear-description"),
        ("comment", "clear-comment"),
    ] {
        if args.contains_id(value) && args.get_flag(clear) {
            return Err(format!("--{value} 与 --{clear} 不能同时使用").into());
        }
    }
    Ok(algorithm)
}

fn metadata(
    args: &clap::ArgMatches,
    value: &str,
    clear: &str,
    previous: &Option<String>,
) -> Result<Option<String>> {
    if args.get_flag(clear) {
        return Ok(None);
    }
    Ok(args
        .get_one::<String>(value)
        .cloned()
        .or_else(|| previous.clone()))
}
