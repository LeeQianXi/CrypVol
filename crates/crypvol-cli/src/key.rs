//! 密钥命令处理。

use std::{
    fs,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use crypvol_core::crypto::{
    CvkEnvelope, CvkPayload, KeyProtection, KeyWrapAlgorithm, KeyWrapFamily, RecipientAlgorithm,
    RecipientKey, load_private_key, load_public_key, unlock, unlock_with_private_key,
};
use zeroize::Zeroizing;

mod generate;
mod info;
mod rekey;
pub(crate) mod storage;
#[cfg(test)]
mod tests;

pub use generate::genkey;
pub use info::info;
pub use rekey::rekey;

pub(crate) type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(crate) fn read_cvk(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    read_cvk_file(&File::open(path)?)
}

fn read_cvk_file(file: &File) -> Result<Zeroizing<Vec<u8>>> {
    const MAX_CVK_SIZE: u64 = 16 + 1024 * 1024 + 256 * 1024 * 1024 + 32;
    if file.metadata()?.len() > MAX_CVK_SIZE {
        return Err("CVK 文件超过格式大小限制".into());
    }
    let mut data = Zeroizing::new(Vec::new());
    file.take(MAX_CVK_SIZE + 1).read_to_end(&mut data)?;
    if data.len() as u64 > MAX_CVK_SIZE {
        return Err("CVK 文件超过格式大小限制".into());
    }
    Ok(data)
}

fn protection(value: &str) -> Result<KeyProtection> {
    if value.eq_ignore_ascii_case("plain") {
        Ok(KeyProtection::Plain)
    } else if value.eq_ignore_ascii_case("password") {
        Ok(KeyProtection::Password)
    } else if value.eq_ignore_ascii_case("publickey") {
        Ok(KeyProtection::PublicKey)
    } else {
        Err("不支持的保护模式".into())
    }
}

fn algorithm(mode: KeyProtection, value: Option<&String>) -> Result<KeyWrapAlgorithm> {
    let algorithm = match value.map(|v| v.to_ascii_lowercase()).as_deref() {
        None => match mode {
            KeyProtection::Plain => KeyWrapAlgorithm::None,
            KeyProtection::Password => KeyWrapAlgorithm::PasswordPbkdf2Sha256,
            KeyProtection::PublicKey => KeyWrapAlgorithm::RsaOaepSha256,
        },
        Some("none") => KeyWrapAlgorithm::None,
        Some("passwordpbkdf2sha256") => KeyWrapAlgorithm::PasswordPbkdf2Sha256,
        Some("passwordargon2id") => KeyWrapAlgorithm::PasswordArgon2Id,
        Some("rsaoaepsha256") => KeyWrapAlgorithm::RsaOaepSha256,
        Some("rsaoaepsha384") => KeyWrapAlgorithm::RsaOaepSha384,
        Some("rsaoaepsha512") => KeyWrapAlgorithm::RsaOaepSha512,
        Some("ecdhp256") => KeyWrapAlgorithm::EcdhP256,
        Some("ecdhp384") => KeyWrapAlgorithm::EcdhP384,
        Some("ecdhp521") => KeyWrapAlgorithm::EcdhP521,
        _ => return Err("不支持的密钥封装算法".into()),
    };
    if algorithm.protection() != mode {
        return Err("保护模式与算法不匹配".into());
    }
    Ok(algorithm)
}

fn read_public_keys(args: &clap::ArgMatches) -> Result<Vec<RecipientKey>> {
    let mut recipients = Vec::new();
    if let Some(paths) = args.get_many::<PathBuf>("public-key") {
        for path in paths {
            let name = path
                .file_stem()
                .and_then(|name| name.to_str())
                .ok_or("公钥文件名无效")?;
            let recipient = load_public_key(&fs::read(path)?, name)?;
            if recipients
                .iter()
                .any(|existing: &RecipientKey| existing.key_id == recipient.key_id)
            {
                return Err(format!("接收者 KeyId 已存在：{}", recipient.key_id).into());
            }
            recipients.push(recipient);
        }
    }
    Ok(recipients)
}

fn add_public_keys(payload: &mut CvkPayload, recipients: Vec<RecipientKey>) -> Result<()> {
    for recipient in recipients {
        if payload
            .recipient_keys
            .iter()
            .any(|existing| existing.key_id == recipient.key_id)
        {
            return Err(format!("接收者 KeyId 已存在：{}", recipient.key_id).into());
        }
        payload.recipient_keys.push(recipient);
    }
    Ok(())
}

fn validate_recipients(
    mode: KeyProtection,
    algorithm: KeyWrapAlgorithm,
    recipients: &[RecipientKey],
) -> Result<()> {
    if mode != KeyProtection::PublicKey {
        return Ok(());
    }
    if recipients.is_empty() {
        return Err("公钥模式至少需要一个接收者".into());
    }
    let expected = match algorithm.family() {
        KeyWrapFamily::Rsa => RecipientAlgorithm::Rsa,
        KeyWrapFamily::Ecdh => RecipientAlgorithm::Ecdh,
        KeyWrapFamily::Plain | KeyWrapFamily::Password => {
            return Err("公钥保护需要 RSA 或 ECDH 封装算法".into());
        }
    };
    if recipients
        .iter()
        .any(|recipient| recipient.algorithm != expected)
    {
        return Err(match expected {
            RecipientAlgorithm::Rsa => "RSA 封装需要 RSA 接收者".into(),
            RecipientAlgorithm::Ecdh => "ECDH 封装需要 ECDH 接收者".into(),
        });
    }
    Ok(())
}

fn unlock_for_command(envelope: &CvkEnvelope<'_>, args: &clap::ArgMatches) -> Result<CvkPayload> {
    match envelope.header().key_protection {
        KeyProtection::Plain => {
            if args.contains_id("password")
                || args.contains_id("privkey-key")
                || args.contains_id("key-pass")
            {
                return Err("明文 CVK 不使用密码或私钥".into());
            }
            Ok(envelope.plain_payload()?)
        }
        KeyProtection::Password => {
            if args.contains_id("privkey-key") || args.contains_id("key-pass") {
                return Err("密码保护 CVK 不使用私钥".into());
            }
            Ok(unlock(
                envelope,
                args.get_one::<String>("password").map(String::as_str),
            )?)
        }
        KeyProtection::PublicKey => {
            if args.contains_id("password") {
                return Err("公钥保护 CVK 不使用 CVK 密码".into());
            }
            let password = args.get_one::<String>("key-pass").map(String::as_str);
            if let Some(path) = args.get_one::<PathBuf>("privkey-key") {
                let private = Zeroizing::new(fs::read(path)?);
                let key = load_private_key(&private, password)?;
                return Ok(unlock_with_private_key(envelope, &key)?);
            }
            let home = std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .ok_or("需要提供 --privkey-key")?;
            let ssh_dir = PathBuf::from(home).join(".ssh");
            let entries =
                fs::read_dir(ssh_dir).map_err(|_| "未找到 SSH 私钥目录，请使用 --privkey-key")?;
            for entry in entries {
                let path = entry?.path();
                if path
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("pub"))
                {
                    let private = path.with_extension("");
                    if let Ok(bytes) = fs::read(private)
                        && let Ok(key) = load_private_key(&Zeroizing::new(bytes), password)
                        && let Ok(payload) = unlock_with_private_key(envelope, &key)
                    {
                        return Ok(payload);
                    }
                }
            }
            Err("未找到能解封 CVK 的私钥，请使用 --privkey-key".into())
        }
    }
}
