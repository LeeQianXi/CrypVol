use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag, aead::AeadInPlace};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Serialize;
use serde_json::json;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use super::{
    CvkEnvelope, CvkHeader, CvkOperation, CvkOperationError, CvkPayload, CvkResult, KeyProtection,
    KeyWrapAlgorithm, cvk::integrity_digest,
};

type InternalResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PayloadForEncoding<'a> {
    cek: &'a str,
    recipient_keys: Vec<serde_json::Value>,
}

pub fn random_cek() -> CvkResult<[u8; 32]> {
    random_cek_inner()
        .map_err(|source| CvkOperationError::from_source(CvkOperation::RandomCek, source))
}

fn random_cek_inner() -> InternalResult<[u8; 32]> {
    let mut cek = [0; 32];
    getrandom::fill(&mut cek).map_err(|_| "随机数生成失败")?;
    tracing::debug!("已生成新的随机 CEK");
    Ok(cek)
}

fn derive(
    password: &str,
    salt: &[u8],
    algorithm: KeyWrapAlgorithm,
    parallelism: u32,
) -> InternalResult<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0; 32]);
    match algorithm {
        KeyWrapAlgorithm::PasswordPbkdf2Sha256 => {
            pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 600_000, &mut *key)
        }
        KeyWrapAlgorithm::PasswordArgon2Id => {
            let params =
                Params::new(65536, 3, parallelism, Some(32)).map_err(|_| "Argon2 参数无效")?;
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into(password.as_bytes(), salt, &mut *key)
                .map_err(|_| "Argon2 派生失败")?;
        }
        _ => return Err("不支持的密码算法".into()),
    }
    Ok(key)
}

pub fn unlock(envelope: &CvkEnvelope<'_>, password: Option<&str>) -> CvkResult<CvkPayload> {
    unlock_with_password_aad(envelope, password, envelope.header_bytes(), &[1])
}

/// 使用调用方提供的认证数据解封密码保护 CVK。
///
/// 原生 CVK 始终使用 Header 原始字节；此接口仅供独立迁移器读取旧格式。
pub fn unlock_with_password_aad(
    envelope: &CvkEnvelope<'_>,
    password: Option<&str>,
    authentication_data: &[u8],
    argon2_parallelism: &[u32],
) -> CvkResult<CvkPayload> {
    unlock_inner(envelope, password, authentication_data, argon2_parallelism)
        .map_err(|source| CvkOperationError::from_source(CvkOperation::PasswordUnlock, source))
}

fn unlock_inner(
    envelope: &CvkEnvelope<'_>,
    password: Option<&str>,
    authentication_data: &[u8],
    argon2_parallelism: &[u32],
) -> InternalResult<CvkPayload> {
    if envelope.header().key_protection == KeyProtection::Plain {
        return Ok(envelope.plain_payload()?);
    }
    if envelope.header().key_protection != KeyProtection::Password {
        return Err("公钥保护模式需要私钥".into());
    }
    let password = password.filter(|p| !p.is_empty()).ok_or("需要提供密码")?;
    let body = envelope.key_body();
    let alg = envelope.header().key_wrap_algorithm;
    tracing::debug!(algorithm = ?alg, "正在解封密码保护 CVK");
    let marker = match alg {
        KeyWrapAlgorithm::PasswordPbkdf2Sha256 => 1,
        KeyWrapAlgorithm::PasswordArgon2Id => 2,
        _ => return Err("不支持的密码算法".into()),
    };
    if body.len() < 45 || body[0] != marker {
        return Err("密码密钥体格式无效".into());
    }
    let parallelism_values: &[u32] = if marker == 2 {
        argon2_parallelism
    } else {
        &[1]
    };
    if parallelism_values.is_empty() {
        return Err("Argon2 并行度不能为空".into());
    }
    for &parallelism in parallelism_values {
        let key = derive(password, &body[1..17], alg, parallelism)?;
        let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| "密钥无效")?;
        let mut plaintext = Zeroizing::new(body[45..].to_vec());
        let decrypt = cipher.decrypt_in_place_detached(
            Nonce::from_slice(&body[17..29]),
            authentication_data,
            &mut plaintext,
            Tag::from_slice(&body[29..45]),
        );
        if decrypt.is_ok() {
            return Ok(CvkPayload::parse(&plaintext)?);
        }
    }
    Err("密码错误或密钥体认证失败".into())
}

pub fn encode(
    header: &CvkHeader,
    payload: &CvkPayload,
    password: Option<&str>,
) -> CvkResult<Vec<u8>> {
    encode_inner(header, payload, password)
        .map_err(|source| CvkOperationError::from_source(CvkOperation::Encode, source))
}

fn encode_inner(
    header: &CvkHeader,
    payload: &CvkPayload,
    password: Option<&str>,
) -> InternalResult<Vec<u8>> {
    header.validate()?;
    tracing::debug!(
        protection = ?header.key_protection,
        algorithm = ?header.key_wrap_algorithm,
        recipients = payload.recipient_keys.len(),
        "正在封装 CVK"
    );
    let header_bytes = serde_json::to_vec(header)?;
    let recipients: Vec<_> = payload.recipient_keys.iter().map(|key| json!({
        "keyId": key.key_id,
        "algorithm": match key.algorithm { super::RecipientAlgorithm::Rsa => "RSA", super::RecipientAlgorithm::Ecdh => "ECDH" },
        "publicKey": STANDARD.encode(&key.public_key),
        "comment": key.comment,
    })).collect();
    let encoded_cek = Zeroizing::new(STANDARD.encode(payload.cek.as_slice()));
    let mut plain = Zeroizing::new(serde_json::to_vec(&PayloadForEncoding {
        cek: &encoded_cek,
        recipient_keys: recipients,
    })?);
    CvkPayload::parse(&plain)?;
    let body = match header.key_protection {
        KeyProtection::Plain => plain.to_vec(),
        KeyProtection::Password => {
            let password = password.filter(|p| !p.is_empty()).ok_or("需要提供密码")?;
            let mut salt = [0; 16];
            let mut nonce = [0; 12];
            getrandom::fill(&mut salt).map_err(|_| "随机数生成失败")?;
            getrandom::fill(&mut nonce).map_err(|_| "随机数生成失败")?;
            // CVK 密钥体没有记录 Argon2 并行度；原生格式固定为 1 以保证跨机器可解封。
            let key = derive(password, &salt, header.key_wrap_algorithm, 1)?;
            let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| "密钥无效")?;
            let tag = cipher
                .encrypt_in_place_detached(Nonce::from_slice(&nonce), &header_bytes, &mut plain)
                .map_err(|_| "密钥体加密失败")?;
            let mut body = Vec::with_capacity(45 + plain.len());
            body.push(
                if header.key_wrap_algorithm == KeyWrapAlgorithm::PasswordPbkdf2Sha256 {
                    1
                } else {
                    2
                },
            );
            body.extend_from_slice(&salt);
            body.extend_from_slice(&nonce);
            body.extend_from_slice(&tag);
            body.extend_from_slice(&plain);
            body
        }
        KeyProtection::PublicKey => {
            super::public_key::protect(header, payload, &header_bytes, &plain)?
        }
    };
    let digest = integrity_digest(&header_bytes, &body);
    let mut output = b"CVK1".to_vec();
    for len in [header_bytes.len(), body.len(), digest.len()] {
        output.extend_from_slice(&u32::try_from(len)?.to_le_bytes());
    }
    output.extend_from_slice(&header_bytes);
    output.extend_from_slice(&body);
    output.extend_from_slice(&digest);
    CvkEnvelope::parse(&output)?;
    Ok(output)
}

impl Drop for CvkPayload {
    fn drop(&mut self) {
        self.cek.zeroize();
    }
}
