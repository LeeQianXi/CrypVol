//! 旧版 CVK 的认证数据兼容层。
//!
//! 此 crate 只服务于迁移或加载旧数据；原生 CVK 的读写不依赖这里的编码规则。

use std::fmt::Write;

use crypvol_core::crypto::{CvkEnvelope, CvkHeader, CvkPayload, unlock_with_password_aad};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub fn unlock_password(
    envelope: &CvkEnvelope<'_>,
    password: Option<&str>,
) -> Result<CvkPayload, Box<dyn std::error::Error>> {
    let authentication_data = legacy_header_bytes(envelope.header())?;
    Ok(unlock_with_password_aad(
        envelope,
        password,
        &authentication_data,
        &[1, 2, 3, 4],
    )?)
}

pub fn legacy_header_bytes(header: &CvkHeader) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut normalized = header.clone();
    if let Some(created_at) = &header.created_at {
        let timestamp = OffsetDateTime::parse(created_at, &Rfc3339)?;
        let mut text = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            timestamp.year(),
            timestamp.month() as u8,
            timestamp.day(),
            timestamp.hour(),
            timestamp.minute(),
            timestamp.second(),
        );
        let ticks = timestamp.nanosecond() / 100;
        if ticks != 0 {
            let fraction = format!("{ticks:07}");
            text.push('.');
            text.push_str(fraction.trim_end_matches('0'));
        }
        let offset = timestamp.offset().whole_minutes();
        write!(
            text,
            "{}{:02}:{:02}",
            if offset < 0 { '-' } else { '+' },
            offset.abs() / 60,
            offset.abs() % 60
        )?;
        normalized.created_at = Some(text);
    }

    let json = serde_json::to_string(&normalized)?;
    let mut encoded = String::with_capacity(json.len());
    let mut chars = json.chars();
    while let Some(character) = chars.next() {
        if character == '\\' {
            let escaped = chars.next().expect("serde_json emits complete escapes");
            match escaped {
                '"' => encoded.push_str("\\u0022"),
                'u' => {
                    encoded.push_str("\\u");
                    for _ in 0..4 {
                        encoded.push(
                            chars
                                .next()
                                .expect("serde_json emits four Unicode escape digits")
                                .to_ascii_uppercase(),
                        );
                    }
                }
                _ => {
                    encoded.push(character);
                    encoded.push(escaped);
                }
            }
        } else if !character.is_ascii()
            || character == '\u{7f}'
            || matches!(character, '<' | '>' | '&' | '\'' | '+' | '`')
        {
            let mut units = [0; 2];
            for unit in character.encode_utf16(&mut units) {
                write!(encoded, "\\u{unit:04X}")?;
            }
        } else {
            encoded.push(character);
        }
    }
    if let Some(start) = encoded.find("\"createdAt\":\"") {
        let value_start = start + "\"createdAt\":\"".len();
        if let Some(end) = encoded[value_start..].find('"') {
            let value_end = value_start + end;
            let value = encoded[value_start..value_end].replace("\\u002B", "+");
            encoded.replace_range(value_start..value_end, &value);
        }
    }
    Ok(encoded.into_bytes())
}
