use std::fmt;

mod payload;
pub use payload::{CvkPayload, RecipientAlgorithm, RecipientKey};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Deserializer, Serialize, de::IntoDeserializer};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const PREFIX_SIZE: usize = 16;
const MAX_HEADER_SIZE: usize = 1024 * 1024;
const MAX_KEY_BODY_SIZE: usize = 256 * 1024 * 1024;
const DIGEST_SIZE: usize = 32;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum KeyProtection {
    Plain,
    Password,
    PublicKey,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum KeyWrapAlgorithm {
    None,
    PasswordPbkdf2Sha256,
    PasswordArgon2Id,
    RsaOaepSha256,
    RsaOaepSha384,
    RsaOaepSha512,
    EcdhP256,
    EcdhP384,
    EcdhP521,
}

/// 密钥封装算法的实现族，用于选择相应的密码学路径。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyWrapFamily {
    Plain,
    Password,
    Rsa,
    Ecdh,
}

impl KeyWrapAlgorithm {
    pub fn family(self) -> KeyWrapFamily {
        match self {
            Self::None => KeyWrapFamily::Plain,
            Self::PasswordPbkdf2Sha256 | Self::PasswordArgon2Id => KeyWrapFamily::Password,
            Self::RsaOaepSha256 | Self::RsaOaepSha384 | Self::RsaOaepSha512 => KeyWrapFamily::Rsa,
            Self::EcdhP256 | Self::EcdhP384 | Self::EcdhP521 => KeyWrapFamily::Ecdh,
        }
    }

    pub fn protection(self) -> KeyProtection {
        match self.family() {
            KeyWrapFamily::Plain => KeyProtection::Plain,
            KeyWrapFamily::Password => KeyProtection::Password,
            KeyWrapFamily::Rsa | KeyWrapFamily::Ecdh => KeyProtection::PublicKey,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CvkHeader {
    pub version: u16,
    #[serde(deserialize_with = "decode_enum")]
    pub key_protection: KeyProtection,
    #[serde(deserialize_with = "decode_enum")]
    pub key_wrap_algorithm: KeyWrapAlgorithm,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generator: Option<String>,
}

impl CvkHeader {
    /// 校验独立于容器字节的 Header 不变量。
    pub fn validate(&self) -> Result<(), CvkError> {
        if self.version == 0 {
            return Err(CvkError::UnsupportedVersion(self.version));
        }
        if self.key_wrap_algorithm.protection() != self.key_protection {
            return Err(CvkError::IncompatibleProtection);
        }
        let Some(created_at) = &self.created_at else {
            return Ok(());
        };
        let timestamp =
            OffsetDateTime::parse(created_at, &Rfc3339).map_err(|_| CvkError::InvalidHeader)?;
        let utc_timestamp = timestamp
            .checked_to_offset(time::UtcOffset::UTC)
            .ok_or(CvkError::InvalidHeader)?;
        let bytes = created_at.as_bytes();
        if bytes.get(10) != Some(&b'T')
            || bytes.last() == Some(&b'z')
            || bytes.get(17..19) == Some(b"60")
            || !(1..=9999).contains(&timestamp.year())
            || !(1..=9999).contains(&utc_timestamp.year())
        {
            return Err(CvkError::InvalidHeader);
        }
        if timestamp.offset().whole_minutes().unsigned_abs() > 14 * 60 {
            return Err(CvkError::InvalidHeader);
        }
        if let Some((_, fraction)) = created_at.split_once('.') {
            let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
            if digits > 16 {
                return Err(CvkError::InvalidHeader);
            }
        }
        Ok(())
    }
}

/// 已通过格式和 SHA-256 校验的 CVK 信封。密钥体借自输入。
pub struct CvkEnvelope<'a> {
    header: CvkHeader,
    header_bytes: &'a [u8],
    key_body: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CvkError {
    Truncated,
    InvalidMagic,
    InvalidLength,
    DigestMismatch,
    InvalidHeader,
    UnsupportedVersion(u16),
    IncompatibleProtection,
    ProtectedPayload,
    InvalidPayload,
    InvalidCek,
    InvalidRecipient,
}

impl fmt::Display for CvkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("CVK 文件截断"),
            Self::InvalidMagic => f.write_str("CVK 魔数无效"),
            Self::InvalidLength => f.write_str("CVK 段长度无效"),
            Self::DigestMismatch => f.write_str("CVK SHA-256 校验失败"),
            Self::InvalidHeader => f.write_str("CVK Header 无效"),
            Self::UnsupportedVersion(version) => write!(f, "CVK 版本不受支持：{version}"),
            Self::IncompatibleProtection => f.write_str("CVK 保护模式与封装算法不匹配"),
            Self::ProtectedPayload => f.write_str("CVK 密钥体需要先解封"),
            Self::InvalidPayload => f.write_str("CVK Payload 无效"),
            Self::InvalidCek => f.write_str("CVK CEK 需要为 32 字节的 Base64 编码"),
            Self::InvalidRecipient => f.write_str("CVK 接收者无效"),
        }
    }
}

impl std::error::Error for CvkError {}

/// CVK 操作的稳定边界，用于让调用方按操作阶段处理失败。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CvkOperation {
    RandomCek,
    Encode,
    PasswordUnlock,
    PublicKeyUnlock,
    PublicKeyLoad,
    PrivateKeyLoad,
}

impl fmt::Display for CvkOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RandomCek => "生成 CEK",
            Self::Encode => "封装 CVK",
            Self::PasswordUnlock => "使用密码解封 CVK",
            Self::PublicKeyUnlock => "使用私钥解封 CVK",
            Self::PublicKeyLoad => "读取公钥",
            Self::PrivateKeyLoad => "读取私钥",
        })
    }
}

/// CVK 密码学操作失败。
#[derive(Debug)]
pub enum CvkOperationError {
    Format(CvkError),
    Failed {
        operation: CvkOperation,
        source: Box<dyn std::error::Error>,
    },
}

impl CvkOperationError {
    pub(super) fn from_source(operation: CvkOperation, source: Box<dyn std::error::Error>) -> Self {
        if let Some(error) = source.downcast_ref::<CvkError>() {
            Self::Format(*error)
        } else {
            Self::Failed { operation, source }
        }
    }

    pub fn operation(&self) -> Option<CvkOperation> {
        match self {
            Self::Format(_) => None,
            Self::Failed { operation, .. } => Some(*operation),
        }
    }
}

impl fmt::Display for CvkOperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(error) => error.fmt(f),
            Self::Failed { operation, source } => write!(f, "{operation}失败：{source}"),
        }
    }
}

impl std::error::Error for CvkOperationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Format(error) => Some(error),
            Self::Failed { source, .. } => Some(source.as_ref()),
        }
    }
}

pub type CvkResult<T> = std::result::Result<T, CvkOperationError>;

impl<'a> CvkEnvelope<'a> {
    pub fn parse(input: &'a [u8]) -> Result<Self, CvkError> {
        let (prefix, records) = input
            .split_first_chunk::<PREFIX_SIZE>()
            .ok_or(CvkError::Truncated)?;
        if &prefix[..4] != b"CVK1" {
            return Err(CvkError::InvalidMagic);
        }
        let header_len = u32::from_le_bytes(prefix[4..8].try_into().unwrap()) as usize;
        let body_len = u32::from_le_bytes(prefix[8..12].try_into().unwrap()) as usize;
        let digest_len = u32::from_le_bytes(prefix[12..16].try_into().unwrap()) as usize;
        if !(1..=MAX_HEADER_SIZE).contains(&header_len)
            || !(1..=MAX_KEY_BODY_SIZE).contains(&body_len)
            || digest_len != DIGEST_SIZE
        {
            return Err(CvkError::InvalidLength);
        }
        let expected = header_len + body_len + DIGEST_SIZE;
        if records.len() < expected {
            return Err(CvkError::Truncated);
        }
        if records.len() != expected {
            return Err(CvkError::InvalidLength);
        }
        let (header_bytes, body_and_digest) = records.split_at(header_len);
        let (key_body, digest) = body_and_digest.split_at(body_len);
        if integrity_digest(header_bytes, key_body).as_slice() != digest {
            return Err(CvkError::DigestMismatch);
        }

        // BOM 参与摘要，但不属于 JSON。
        let json = header_bytes
            .strip_prefix(b"\xef\xbb\xbf")
            .unwrap_or(header_bytes);
        let header: CvkHeader = decode_object(json, CvkError::InvalidHeader)?;
        header.validate()?;
        tracing::debug!(
            header_bytes = header_len,
            key_body_bytes = body_len,
            protection = ?header.key_protection,
            algorithm = ?header.key_wrap_algorithm,
            "CVK 信封已通过格式和摘要校验"
        );
        Ok(Self {
            header,
            header_bytes,
            key_body,
        })
    }

    pub fn header(&self) -> &CvkHeader {
        &self.header
    }

    pub fn header_bytes(&self) -> &'a [u8] {
        self.header_bytes
    }

    pub fn key_body(&self) -> &'a [u8] {
        self.key_body
    }

    pub fn plain_payload(&self) -> Result<CvkPayload, CvkError> {
        if self.header.key_protection != KeyProtection::Plain {
            return Err(CvkError::ProtectedPayload);
        }
        CvkPayload::parse(self.key_body)
    }
}

pub(super) fn decode_enum<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let value = String::deserialize(deserializer)?;
    T::deserialize(value.into_deserializer())
}

pub(super) fn decode_object<'a, T: Deserialize<'a>>(
    bytes: &'a [u8],
    error: CvkError,
) -> Result<T, CvkError> {
    // Serde 也支持按字段顺序反序列化结构体，CVK 则只允许 JSON 对象。
    if !bytes.trim_ascii_start().starts_with(b"{") {
        return Err(error);
    }
    serde_json::from_slice(bytes).map_err(|_| error)
}

pub(super) fn decode_base64(value: &str, error: CvkError) -> Result<Vec<u8>, CvkError> {
    // 与 .NET Convert.FromBase64String 一致，允许四种 ASCII 空白。
    let is_space = |byte| matches!(byte, b' ' | b'\r' | b'\n' | b'\t');
    if value.bytes().any(is_space) {
        let compact: Vec<_> = value.bytes().filter(|&byte| !is_space(byte)).collect();
        STANDARD.decode(compact).map_err(|_| error)
    } else {
        STANDARD.decode(value).map_err(|_| error)
    }
}

pub(super) fn integrity_digest(header: &[u8], body: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut digest = Sha256::new();
    hash_base64(&mut digest, header);
    digest.update(b".");
    hash_base64(&mut digest, body);
    digest.finalize().into()
}

fn hash_base64(digest: &mut Sha256, bytes: &[u8]) {
    // 每个非末块含完整的 Base64 三字节组，避免为大型密钥体分配编码缓冲。
    let mut encoded = [0; 4096];
    for chunk in bytes.chunks(3072) {
        let len = URL_SAFE_NO_PAD
            .encode_slice(chunk, &mut encoded)
            .expect("4096 bytes fit the encoding of 3072 bytes");
        digest.update(&encoded[..len]);
    }
}
