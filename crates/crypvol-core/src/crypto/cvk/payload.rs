use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use zeroize::Zeroizing;

use super::{CvkError, decode_base64, decode_enum, decode_object};

/// 解封后的密钥内容。
pub struct CvkPayload {
    pub cek: [u8; 32],
    pub recipient_keys: Vec<RecipientKey>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum RecipientAlgorithm {
    #[serde(rename = "RSA")]
    Rsa,
    #[serde(rename = "ECDH")]
    Ecdh,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientKey {
    pub key_id: String,
    pub algorithm: RecipientAlgorithm,
    pub public_key: Vec<u8>,
    pub comment: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PayloadJson<'a> {
    cek: String,
    #[serde(borrow)]
    recipient_keys: Vec<&'a RawValue>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecipientJson {
    key_id: String,
    #[serde(deserialize_with = "decode_enum")]
    algorithm: RecipientAlgorithm,
    public_key: String,
    comment: Option<String>,
}

impl CvkPayload {
    /// 解析明文或经认证解封后的 JSON。
    pub fn parse(input: &[u8]) -> Result<Self, CvkError> {
        let payload: PayloadJson<'_> = decode_object(input, CvkError::InvalidPayload)?;
        let encoded_cek = Zeroizing::new(payload.cek);
        let decoded_cek = Zeroizing::new(decode_base64(&encoded_cek, CvkError::InvalidCek)?);
        let cek = decoded_cek
            .as_slice()
            .try_into()
            .map_err(|_| CvkError::InvalidCek)?;

        let mut recipient_keys = Vec::with_capacity(payload.recipient_keys.len());
        for raw in payload.recipient_keys {
            let recipient: RecipientJson =
                decode_object(raw.get().as_bytes(), CvkError::InvalidRecipient)?;
            let public_key = decode_base64(&recipient.public_key, CvkError::InvalidRecipient)?;
            if recipient.key_id.trim().is_empty() || public_key.is_empty() {
                return Err(CvkError::InvalidRecipient);
            }
            recipient_keys.push(RecipientKey {
                key_id: recipient.key_id,
                algorithm: recipient.algorithm,
                public_key,
                comment: recipient.comment,
            });
        }
        let mut ids = HashSet::with_capacity(recipient_keys.len());
        if recipient_keys
            .iter()
            .any(|recipient| !ids.insert(recipient.key_id.as_str()))
        {
            return Err(CvkError::InvalidRecipient);
        }
        Ok(Self {
            cek,
            recipient_keys,
        })
    }
}
