use std::path::{Path, PathBuf};

use crypvol_core::crypto::{CvkHeader, CvkPayload, KeyProtection, encode, random_cek};
use zeroize::Zeroizing;

use super::{Result, algorithm, protection, read_public_keys, storage, validate_recipients};

pub fn genkey(args: &clap::ArgMatches) -> Result<()> {
    let supplied_cek = args.get_one::<String>("cek");
    if let Some(hex) = supplied_cek
        && (hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err("--cek 需要 64 个十六进制字符".into());
    }
    let mode = protection(args.get_one::<String>("mode").unwrap())?;
    let algorithm = algorithm(mode, args.get_one::<String>("algorithm"))?;
    let password = args.get_one::<String>("password").map(String::as_str);
    if mode != KeyProtection::Password && password.is_some() {
        return Err("只有密码保护模式可以使用 --password".into());
    }
    if mode == KeyProtection::Password && password.is_none_or(|value| value.trim().is_empty()) {
        return Err("密码保护模式需要非空密码".into());
    }
    if mode != KeyProtection::PublicKey && args.contains_id("public-key") {
        return Err("接收者选项需要公钥保护模式".into());
    }
    let recipient_keys = read_public_keys(args)?;
    validate_recipients(mode, algorithm, &recipient_keys)?;
    let cek = if let Some(hex) = supplied_cek {
        let mut cek = [0; 32];
        for (byte, pair) in cek.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
            *byte = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
        }
        cek
    } else {
        random_cek()?
    };
    let payload = CvkPayload {
        cek,
        recipient_keys,
    };
    let header = CvkHeader {
        version: 1,
        key_protection: mode,
        key_wrap_algorithm: algorithm,
        label: None,
        description: None,
        comment: args.get_one::<String>("comment").cloned(),
        created_at: None,
        generator: Some("CrypVol Rust".into()),
    };
    let name = args.get_one::<String>("name").unwrap();
    if name.trim().is_empty()
        || Path::new(name).components().count() != 1
        || name == "."
        || name == ".."
        || name.to_lowercase().ends_with(".cvk")
    {
        return Err("密钥名称必须是单个文件名且不含 .cvk 扩展名".into());
    }
    let output = args
        .get_one::<PathBuf>("output")
        .unwrap()
        .join(format!("{name}.cvk"));
    let data = Zeroizing::new(encode(&header, &payload, password)?);
    storage::create(&output, &data)?;
    println!("已创建 {}", output.display());
    Ok(())
}
