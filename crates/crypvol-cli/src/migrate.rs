//! 旧版 CVK 迁移命令。

use std::{fs, path::PathBuf};

use crypvol_core::crypto::{
    CvkEnvelope, CvkPayload, KeyProtection, encode, load_private_key, unlock_with_private_key_aad,
};
use crypvol_migrate::{legacy_header_bytes, unlock_password};
use zeroize::Zeroizing;

use crate::key::{Result, read_cvk, storage};

pub(crate) fn run(args: &clap::ArgMatches) -> Result<()> {
    let source = args.get_one::<PathBuf>("cvk").expect("CVK is required");
    let output = args
        .get_one::<PathBuf>("output")
        .expect("output is required");
    if source == output {
        return Err("迁移输出不能覆盖旧 CVK，请指定新路径".into());
    }
    let data = read_cvk(source)?;
    let envelope = CvkEnvelope::parse(&data)?;
    validate_credentials(&envelope, args)?;
    let payload = unlock_legacy(&envelope, args)?;
    let password = if envelope.header().key_protection == KeyProtection::Password {
        args.get_one::<String>("password").map(String::as_str)
    } else {
        None
    };
    let native = Zeroizing::new(encode(envelope.header(), &payload, password)?);
    storage::create(output, &native)?;
    println!("已迁移 {} 到 {}", source.display(), output.display());
    Ok(())
}

fn validate_credentials(envelope: &CvkEnvelope<'_>, args: &clap::ArgMatches) -> Result<()> {
    let has_password = args.contains_id("password");
    let has_private_key = args.contains_id("privkey-key");
    let has_private_key_password = args.contains_id("key-pass");
    match envelope.header().key_protection {
        KeyProtection::Plain if has_password || has_private_key || has_private_key_password => {
            Err("明文旧 CVK 不使用密码或私钥".into())
        }
        KeyProtection::Password if has_private_key || has_private_key_password => {
            Err("密码保护旧 CVK 不使用私钥".into())
        }
        KeyProtection::PublicKey if has_password => Err("公钥保护旧 CVK 不使用 CVK 密码".into()),
        _ => Ok(()),
    }
}

fn unlock_legacy(envelope: &CvkEnvelope<'_>, args: &clap::ArgMatches) -> Result<CvkPayload> {
    match envelope.header().key_protection {
        KeyProtection::Plain => Ok(envelope.plain_payload()?),
        KeyProtection::Password => Ok(unlock_password(
            envelope,
            args.get_one::<String>("password").map(String::as_str),
        )?),
        KeyProtection::PublicKey => {
            let path = args
                .get_one::<PathBuf>("privkey-key")
                .ok_or("迁移公钥保护 CVK 时需要提供 --privkey-key，自动发现不会读取旧密钥")?;
            let private = Zeroizing::new(fs::read(path)?);
            let key = load_private_key(
                &private,
                args.get_one::<String>("key-pass").map(String::as_str),
            )?;
            let aad = legacy_header_bytes(envelope.header())?;
            Ok(unlock_with_private_key_aad(envelope, &key, &aad)?)
        }
    }
}
