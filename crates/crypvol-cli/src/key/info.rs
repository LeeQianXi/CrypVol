use std::{borrow::Cow, path::PathBuf};

use crypvol_core::crypto::{CvkEnvelope, RecipientAlgorithm};
use sha2::{Digest, Sha256};

use super::{Result, read_cvk, unlock_for_command};

pub fn info(args: &clap::ArgMatches) -> Result<()> {
    let path = args.get_one::<PathBuf>("cvk").expect("CVK is required");
    let data = read_cvk(path)?;
    let envelope = CvkEnvelope::parse(&data)?;
    let header = envelope.header();

    println!("版本：{}", header.version);
    println!("保护方式：{:?}", header.key_protection);
    println!("封装算法：{:?}", header.key_wrap_algorithm);
    for (label, value) in [
        ("标签", &header.label),
        ("描述", &header.description),
        ("注释", &header.comment),
        ("创建时间", &header.created_at),
        ("生成器", &header.generator),
    ] {
        if let Some(value) = value {
            println!("{label}：{}", display_text(value));
        }
    }
    println!("文件摘要：已校验（不提供认证）");
    let payload = unlock_for_command(&envelope, args)?;
    let fingerprint = Sha256::digest(payload.cek.as_slice());
    println!("密钥体：已解封并验证");
    println!("接收者数：{}", payload.recipient_keys.len());
    for recipient in &payload.recipient_keys {
        let algorithm = match recipient.algorithm {
            RecipientAlgorithm::Rsa => "RSA",
            RecipientAlgorithm::Ecdh => "ECDH",
        };
        println!("  {} ({algorithm})", display_text(&recipient.key_id));
    }
    print!("CEK 指纹：");
    for byte in &fingerprint[..8] {
        print!("{byte:02X}");
    }
    println!("...");
    Ok(())
}

/// 将外部元数据限制为单行终端文本，避免 CVK 内容改变终端控制状态。
fn display_text(value: &str) -> Cow<'_, str> {
    if !value.chars().any(|character| character.is_control()) {
        return Cow::Borrowed(value);
    }
    let mut displayed = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\n' => displayed.push_str("\\n"),
            '\r' => displayed.push_str("\\r"),
            '\t' => displayed.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write;
                write!(displayed, "\\u{{{:X}}}", character as u32)
                    .expect("writing to String cannot fail");
            }
            character => displayed.push(character),
        }
    }
    Cow::Owned(displayed)
}

#[cfg(test)]
mod tests {
    use super::display_text;

    #[test]
    fn display_text_preserves_text_and_escapes_terminal_controls() {
        assert_eq!(display_text("中文 comment"), "中文 comment");
        assert_eq!(display_text("line\n\x1b[2J"), "line\\n\\u{1B}[2J");
    }
}
