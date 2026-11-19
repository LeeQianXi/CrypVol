use std::collections::HashSet;

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag, aead::AeadInPlace};
use base64::{Engine, engine::general_purpose::STANDARD};
use openssl::{
    encrypt::{Decrypter, Encrypter},
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Padding,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::super::{
    CvkEnvelope, CvkError, CvkHeader, CvkPayload, KeyWrapAlgorithm, RecipientAlgorithm,
    cvk::decode_base64,
};
use super::{InternalResult, Recipient, recipient_json};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RsaRecipient {
    key_id: String,
    wrapped_key: String,
    #[serde(deserialize_with = "super::deserialize_object")]
    recipient: Recipient,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RsaBody {
    nonce: String,
    tag: String,
    ciphertext: String,
    #[serde(deserialize_with = "super::deserialize_recipients")]
    recipients: Vec<Option<RsaRecipient>>,
}

fn rsa_digest(algorithm: KeyWrapAlgorithm) -> InternalResult<MessageDigest> {
    match algorithm {
        KeyWrapAlgorithm::RsaOaepSha256 => Ok(MessageDigest::sha256()),
        KeyWrapAlgorithm::RsaOaepSha384 => Ok(MessageDigest::sha384()),
        KeyWrapAlgorithm::RsaOaepSha512 => Ok(MessageDigest::sha512()),
        _ => Err("不支持的公钥封装算法".into()),
    }
}

pub(super) fn protect(
    header: &CvkHeader,
    payload: &CvkPayload,
    aad: &[u8],
    plaintext: &[u8],
) -> InternalResult<Vec<u8>> {
    let digest = rsa_digest(header.key_wrap_algorithm)?;
    if payload.recipient_keys.is_empty() {
        return Err("公钥模式至少需要一个接收者".into());
    }
    let mut recipient_keys = Vec::with_capacity(payload.recipient_keys.len());
    for recipient in &payload.recipient_keys {
        if recipient.algorithm != RecipientAlgorithm::Rsa {
            return Err("RSA 封装需要 RSA 接收者".into());
        }
        recipient_keys.push((recipient, PKey::public_key_from_der(&recipient.public_key)?));
    }
    let mut data_key = Zeroizing::new([0; 32]);
    let mut nonce = [0; 12];
    getrandom::fill(&mut *data_key).map_err(|_| "随机数生成失败")?;
    getrandom::fill(&mut nonce).map_err(|_| "随机数生成失败")?;
    let cipher = Aes256Gcm::new_from_slice(&*data_key).map_err(|_| "密钥无效")?;
    let mut ciphertext = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), aad, &mut ciphertext)
        .map_err(|_| "密钥体加密失败")?;
    let mut recipients = Vec::with_capacity(recipient_keys.len());
    for (recipient, key) in recipient_keys {
        let mut encrypter = Encrypter::new(&key)?;
        encrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
        encrypter.set_rsa_oaep_md(digest)?;
        encrypter.set_rsa_mgf1_md(digest)?;
        let mut wrapped = vec![0; encrypter.encrypt_len(&*data_key)?];
        let len = encrypter.encrypt(&*data_key, &mut wrapped)?;
        wrapped.truncate(len);
        recipients.push(Some(RsaRecipient {
            key_id: recipient.key_id.clone(),
            wrapped_key: STANDARD.encode(wrapped),
            recipient: recipient_json(recipient),
        }));
    }
    Ok(serde_json::to_vec(&RsaBody {
        nonce: STANDARD.encode(nonce),
        tag: STANDARD.encode(tag),
        ciphertext: STANDARD.encode(ciphertext),
        recipients,
    })?)
}

/// 用指定私钥尝试 CVK 中的所有匹配接收者。
pub(super) fn unlock(
    envelope: &CvkEnvelope<'_>,
    key: &PKey<Private>,
    authentication_data: &[u8],
) -> InternalResult<CvkPayload> {
    let digest = rsa_digest(envelope.header().key_wrap_algorithm)?;
    let body: RsaBody = super::decode_object(envelope.key_body(), CvkError::InvalidPayload)?;
    if !body.recipients.iter().any(Option::is_some) {
        return Err("CVK 缺少接收者".into());
    }
    let nonce = decode_base64(&body.nonce, CvkError::InvalidPayload)?;
    let tag = decode_base64(&body.tag, CvkError::InvalidPayload)?;
    if nonce.len() != 12 || tag.len() != 16 {
        return Err("CVK 密钥体格式无效".into());
    }
    let ciphertext = decode_base64(&body.ciphertext, CvkError::InvalidPayload)?;
    let mut ids = HashSet::new();
    for entry in body.recipients.iter().flatten() {
        if entry.key_id.trim().is_empty()
            || !ids.insert(&entry.key_id)
            || entry.recipient.key_id != entry.key_id
            || entry.recipient.algorithm != RecipientAlgorithm::Rsa
            || decode_base64(&entry.recipient.public_key, CvkError::InvalidRecipient)?.is_empty()
        {
            return Err("CVK 接收者无效".into());
        }
    }
    for entry in body.recipients.into_iter().flatten() {
        let Ok(wrapped) = decode_base64(&entry.wrapped_key, CvkError::InvalidPayload) else {
            continue;
        };
        let mut decrypter = Decrypter::new(key)?;
        decrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
        decrypter.set_rsa_oaep_md(digest)?;
        decrypter.set_rsa_mgf1_md(digest)?;
        let Ok(length) = decrypter.decrypt_len(&wrapped) else {
            continue;
        };
        let mut data_key = Zeroizing::new(vec![0; length]);
        let Ok(size) = decrypter.decrypt(&wrapped, &mut data_key) else {
            continue;
        };
        if size != 32 {
            continue;
        }
        let cipher = Aes256Gcm::new_from_slice(&data_key[..size]).map_err(|_| "密钥无效")?;
        let mut plaintext = Zeroizing::new(ciphertext.clone());
        if cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                authentication_data,
                &mut plaintext,
                Tag::from_slice(&tag),
            )
            .is_ok()
        {
            return Ok(CvkPayload::parse(&plaintext)?);
        }
    }
    Err("没有能解封 CVK 的私钥，或密钥体认证失败".into())
}
