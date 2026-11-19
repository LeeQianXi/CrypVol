//! CVK 公钥接收者的密钥材料和封装。

use base64::{Engine, engine::general_purpose::STANDARD};
use openssl::pkey::{PKey, Private};
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use serde_json::value::RawValue;

use super::{
    CvkEnvelope, CvkError, CvkHeader, CvkOperation, CvkOperationError, CvkPayload, CvkResult,
    KeyWrapFamily, RecipientAlgorithm, RecipientKey, cvk::decode_object,
};

mod ecdh;
mod load;
mod rsa;

pub use load::{load_private_key, load_public_key, private_key_requires_password};

pub(super) type InternalResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Recipient {
    key_id: String,
    #[serde(deserialize_with = "super::cvk::decode_enum")]
    algorithm: RecipientAlgorithm,
    public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
}

fn recipient_json(recipient: &RecipientKey) -> Recipient {
    Recipient {
        key_id: recipient.key_id.clone(),
        algorithm: recipient.algorithm,
        public_key: STANDARD.encode(&recipient.public_key),
        comment: recipient.comment.clone(),
    }
}

fn deserialize_object<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    use serde::de::Error;
    let value = Box::<RawValue>::deserialize(deserializer)?;
    decode_object(value.get().as_bytes(), CvkError::InvalidPayload).map_err(D::Error::custom)
}

fn deserialize_recipients<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Vec<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    use serde::de::Error;
    let values = Vec::<Option<Box<RawValue>>>::deserialize(deserializer)?;
    values
        .into_iter()
        .map(|value| {
            value
                .map(|value| decode_object(value.get().as_bytes(), CvkError::InvalidRecipient))
                .transpose()
                .map_err(D::Error::custom)
        })
        .collect()
}

/// 使用所选公钥算法封装载荷。
pub(super) fn protect(
    header: &CvkHeader,
    payload: &CvkPayload,
    aad: &[u8],
    plaintext: &[u8],
) -> InternalResult<Vec<u8>> {
    tracing::debug!(
        algorithm = ?header.key_wrap_algorithm,
        recipients = payload.recipient_keys.len(),
        "正在使用公钥保护封装 CVK"
    );
    match header.key_wrap_algorithm.family() {
        KeyWrapFamily::Ecdh => ecdh::protect(header, payload, aad, plaintext),
        KeyWrapFamily::Rsa => rsa::protect(header, payload, aad, plaintext),
        KeyWrapFamily::Plain | KeyWrapFamily::Password => {
            Err("公钥保护需要 RSA 或 ECDH 封装算法".into())
        }
    }
}

/// 使用指定私钥解封 CVK。
pub fn unlock_with_private_key(
    envelope: &CvkEnvelope<'_>,
    key: &PKey<Private>,
) -> CvkResult<CvkPayload> {
    unlock_with_private_key_aad(envelope, key, envelope.header_bytes())
}

/// 使用调用方提供的认证数据解封公钥保护 CVK。
///
/// 原生 CVK 始终使用 Header 原始字节；此接口仅供独立迁移器读取旧格式。
pub fn unlock_with_private_key_aad(
    envelope: &CvkEnvelope<'_>,
    key: &PKey<Private>,
    authentication_data: &[u8],
) -> CvkResult<CvkPayload> {
    unlock_with_private_key_inner(envelope, key, authentication_data)
        .map_err(|source| CvkOperationError::from_source(CvkOperation::PublicKeyUnlock, source))
}

fn unlock_with_private_key_inner(
    envelope: &CvkEnvelope<'_>,
    key: &PKey<Private>,
    authentication_data: &[u8],
) -> InternalResult<CvkPayload> {
    tracing::debug!(
        algorithm = ?envelope.header().key_wrap_algorithm,
        "正在使用私钥解封 CVK"
    );
    match envelope.header().key_wrap_algorithm.family() {
        KeyWrapFamily::Ecdh => ecdh::unlock(envelope, key, authentication_data),
        KeyWrapFamily::Rsa => rsa::unlock(envelope, key, authentication_data),
        KeyWrapFamily::Plain | KeyWrapFamily::Password => Err("当前 CVK 不使用公钥保护".into()),
    }
}
