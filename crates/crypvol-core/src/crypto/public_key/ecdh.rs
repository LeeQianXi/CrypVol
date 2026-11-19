use std::collections::HashSet;

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag, aead::AeadInPlace};
use base64::{Engine, engine::general_purpose::STANDARD};
use openssl::{
    derive::Deriver,
    ec::{EcGroup, EcKey},
    md::Md,
    nid::Nid,
    pkey::{PKey, Private, Public},
    pkey_ctx::PkeyCtx,
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
struct EcdhRecipient {
    key_id: String,
    ephemeral_public_key: String,
    nonce: String,
    tag: String,
    wrapped_key: String,
    #[serde(deserialize_with = "super::deserialize_object")]
    recipient: Recipient,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EcdhBody {
    data_nonce: String,
    data_tag: String,
    ciphertext: String,
    #[serde(deserialize_with = "super::deserialize_recipients")]
    recipients: Vec<Option<EcdhRecipient>>,
}

pub(super) fn curve(algorithm: KeyWrapAlgorithm) -> InternalResult<Nid> {
    match algorithm {
        KeyWrapAlgorithm::EcdhP256 => Ok(Nid::X9_62_PRIME256V1),
        KeyWrapAlgorithm::EcdhP384 => Ok(Nid::SECP384R1),
        KeyWrapAlgorithm::EcdhP521 => Ok(Nid::SECP521R1),
        _ => Err("不支持的 ECDH 算法".into()),
    }
}

fn ecdh_wrap_key(
    private: &PKey<Private>,
    public: &PKey<Public>,
) -> InternalResult<Zeroizing<[u8; 32]>> {
    let mut deriver = Deriver::new(private)?;
    deriver.set_peer(public)?;
    let shared = Zeroizing::new(deriver.derive_to_vec()?);
    let shared_hash = Zeroizing::new(openssl::sha::sha256(&shared));
    let mut context = PkeyCtx::new_id(openssl::pkey::Id::HKDF)?;
    context.derive_init()?;
    context.set_hkdf_md(Md::sha256())?;
    context.set_hkdf_key(&*shared_hash)?;
    context.add_hkdf_info(b"CrypVol CVK ECDH")?;
    let mut output = Zeroizing::new([0; 32]);
    context.derive(Some(&mut *output))?;
    Ok(output)
}

pub(super) fn protect(
    header: &CvkHeader,
    payload: &CvkPayload,
    aad: &[u8],
    plaintext: &[u8],
) -> InternalResult<Vec<u8>> {
    if payload.recipient_keys.is_empty() {
        return Err("公钥模式至少需要一个接收者".into());
    }
    let group = EcGroup::from_curve_name(curve(header.key_wrap_algorithm)?)?;
    let mut recipient_keys = Vec::with_capacity(payload.recipient_keys.len());
    for recipient in &payload.recipient_keys {
        if recipient.algorithm != RecipientAlgorithm::Ecdh {
            return Err("ECDH 封装需要 ECDH 接收者".into());
        }
        let public = PKey::public_key_from_der(&recipient.public_key)?;
        if public.ec_key()?.group().curve_name() != group.curve_name() {
            return Err("接收者公钥曲线与封装算法不匹配".into());
        }
        recipient_keys.push((recipient, public));
    }
    let mut data_key = Zeroizing::new([0; 32]);
    let mut data_nonce = [0; 12];
    getrandom::fill(&mut *data_key).map_err(|_| "随机数生成失败")?;
    getrandom::fill(&mut data_nonce).map_err(|_| "随机数生成失败")?;
    let cipher = Aes256Gcm::new_from_slice(&*data_key).map_err(|_| "密钥无效")?;
    let mut ciphertext = plaintext.to_vec();
    let data_tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&data_nonce), aad, &mut ciphertext)
        .map_err(|_| "密钥体加密失败")?;
    let mut recipients = Vec::with_capacity(recipient_keys.len());
    for (recipient, public) in recipient_keys {
        let ephemeral = PKey::from_ec_key(EcKey::generate(&group)?)?;
        let wrap_key = ecdh_wrap_key(&ephemeral, &public)?;
        let wrap_cipher = Aes256Gcm::new_from_slice(&*wrap_key).map_err(|_| "密钥无效")?;
        let mut nonce = [0; 12];
        getrandom::fill(&mut nonce).map_err(|_| "随机数生成失败")?;
        let mut wrapped = Zeroizing::new(data_key.to_vec());
        let tag = wrap_cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), b"", &mut wrapped)
            .map_err(|_| "密钥封装失败")?;
        recipients.push(Some(EcdhRecipient {
            key_id: recipient.key_id.clone(),
            ephemeral_public_key: STANDARD.encode(ephemeral.public_key_to_der()?),
            nonce: STANDARD.encode(nonce),
            tag: STANDARD.encode(tag),
            wrapped_key: STANDARD.encode(&*wrapped),
            recipient: recipient_json(recipient),
        }));
    }
    Ok(serde_json::to_vec(&EcdhBody {
        data_nonce: STANDARD.encode(data_nonce),
        data_tag: STANDARD.encode(data_tag),
        ciphertext: STANDARD.encode(ciphertext),
        recipients,
    })?)
}

pub(super) fn unlock(
    envelope: &CvkEnvelope<'_>,
    private: &PKey<Private>,
    authentication_data: &[u8],
) -> InternalResult<CvkPayload> {
    let expected_curve = curve(envelope.header().key_wrap_algorithm)?;
    if private.ec_key()?.group().curve_name() != Some(expected_curve) {
        return Err("私钥曲线与封装算法不匹配".into());
    }
    let body: EcdhBody = super::decode_object(envelope.key_body(), CvkError::InvalidPayload)?;
    if !body.recipients.iter().any(Option::is_some) {
        return Err("CVK 缺少接收者".into());
    }
    let data_nonce = decode_base64(&body.data_nonce, CvkError::InvalidPayload)?;
    let data_tag = decode_base64(&body.data_tag, CvkError::InvalidPayload)?;
    let ciphertext = decode_base64(&body.ciphertext, CvkError::InvalidPayload)?;
    if data_nonce.len() != 12 || data_tag.len() != 16 {
        return Err("CVK 密钥体格式无效".into());
    }
    let mut ids = HashSet::new();
    for entry in body.recipients.iter().flatten() {
        if entry.key_id.trim().is_empty()
            || !ids.insert(&entry.key_id)
            || entry.recipient.key_id != entry.key_id
            || entry.recipient.algorithm != RecipientAlgorithm::Ecdh
            || decode_base64(&entry.recipient.public_key, CvkError::InvalidRecipient)?.is_empty()
        {
            return Err("CVK 接收者无效".into());
        }
    }
    for entry in body.recipients.into_iter().flatten() {
        let Ok(wrapped) = unwrap_ecdh_recipient(&entry, private, expected_curve) else {
            continue;
        };
        let cipher = Aes256Gcm::new_from_slice(&wrapped).map_err(|_| "密钥无效")?;
        let mut plaintext = Zeroizing::new(ciphertext.clone());
        if cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&data_nonce),
                authentication_data,
                &mut plaintext,
                Tag::from_slice(&data_tag),
            )
            .is_ok()
        {
            return Ok(CvkPayload::parse(&plaintext)?);
        }
    }
    Err("没有能解封 CVK 的私钥，或密钥体认证失败".into())
}

fn unwrap_ecdh_recipient(
    entry: &EcdhRecipient,
    private: &PKey<Private>,
    expected_curve: Nid,
) -> InternalResult<Zeroizing<Vec<u8>>> {
    let nonce = decode_base64(&entry.nonce, CvkError::InvalidPayload)?;
    let tag = decode_base64(&entry.tag, CvkError::InvalidPayload)?;
    let mut wrapped = Zeroizing::new(decode_base64(&entry.wrapped_key, CvkError::InvalidPayload)?);
    if nonce.len() != 12 || tag.len() != 16 || wrapped.len() != 32 {
        return Err("ECDH 接收者格式无效".into());
    }
    let ephemeral = PKey::public_key_from_der(&decode_base64(
        &entry.ephemeral_public_key,
        CvkError::InvalidPayload,
    )?)?;
    if ephemeral.ec_key()?.group().curve_name() != Some(expected_curve) {
        return Err("ECDH 临时公钥曲线不匹配".into());
    }
    let wrap_key = ecdh_wrap_key(private, &ephemeral)?;
    let cipher = Aes256Gcm::new_from_slice(&*wrap_key).map_err(|_| "密钥无效")?;
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            b"",
            &mut wrapped,
            Tag::from_slice(&tag),
        )
        .map_err(|_| "ECDH 接收者解封失败")?;
    Ok(wrapped)
}
