use openssl::{
    bn::{BigNum, BigNumContext},
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::X509,
};
use ssh_key::{private::KeypairData, public::KeyData};

use super::super::{RecipientAlgorithm, RecipientKey};
use super::{CvkOperation, CvkOperationError, CvkResult, InternalResult};

/// 将 PEM 或 OpenSSH 公钥转换为 CVK 接收者。
pub fn load_public_key(data: &[u8], fallback_id: &str) -> CvkResult<RecipientKey> {
    load_public_key_inner(data, fallback_id)
        .map_err(|source| CvkOperationError::from_source(CvkOperation::PublicKeyLoad, source))
}

fn load_public_key_inner(data: &[u8], fallback_id: &str) -> InternalResult<RecipientKey> {
    let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    let (key, key_id) = if let Ok(text) = std::str::from_utf8(data)
        && let Some(line) = text
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty() && !line.starts_with('#'))
        && line.starts_with("ssh-")
    {
        let key = ssh_key::PublicKey::from_openssh(line)?;
        let KeyData::Rsa(rsa) = key.key_data() else {
            return Err("不支持的 OpenSSH 公钥算法".into());
        };
        let n = BigNum::from_slice(rsa.n.as_positive_bytes().ok_or("RSA 模数无效")?)?;
        let e = BigNum::from_slice(rsa.e.as_positive_bytes().ok_or("RSA 指数无效")?)?;
        let key_id = if key.comment().is_empty() {
            fallback_id
        } else {
            key.comment()
        };
        (
            PKey::from_rsa(Rsa::from_public_components(n, e)?)?,
            key_id.to_owned(),
        )
    } else {
        if data
            .windows(b"PRIVATE KEY".len())
            .any(|window| window.eq_ignore_ascii_case(b"PRIVATE KEY"))
        {
            return Err("公钥文件包含私钥".into());
        }
        let key = PKey::public_key_from_pem(data)
            .or_else(|_| Rsa::public_key_from_pem_pkcs1(data).and_then(PKey::from_rsa))
            .or_else(|_| X509::from_pem(data).and_then(|cert| cert.public_key()))?;
        (key, fallback_id.to_owned())
    };
    if key_id.trim().is_empty() {
        return Err("接收者 KeyId 不能为空".into());
    }
    let algorithm = match key.id() {
        openssl::pkey::Id::RSA => RecipientAlgorithm::Rsa,
        openssl::pkey::Id::EC => RecipientAlgorithm::Ecdh,
        _ => return Err("不支持的公钥算法".into()),
    };
    Ok(RecipientKey {
        key_id,
        algorithm,
        public_key: key.public_key_to_der()?,
        comment: None,
    })
}

/// 检测 PEM 或 OpenSSH 私钥是否需要解密密码，无效输入返回错误。
pub fn private_key_requires_password(data: &[u8]) -> CvkResult<bool> {
    private_key_requires_password_inner(data)
        .map_err(|source| CvkOperationError::from_source(CvkOperation::PrivateKeyLoad, source))
}

fn private_key_requires_password_inner(data: &[u8]) -> InternalResult<bool> {
    let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    if data.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----") {
        return Ok(ssh_key::PrivateKey::from_openssh(data)?.is_encrypted());
    }
    let requested = std::cell::Cell::new(false);
    let result = PKey::private_key_from_pem_callback(data, |_| {
        requested.set(true);
        Err(openssl::error::ErrorStack::get())
    });
    if requested.get() {
        return Ok(true);
    }
    result?;
    Ok(false)
}

/// 读取 PEM 或 OpenSSH 私钥。私钥密码仅用于解密密钥文件。
pub fn load_private_key(data: &[u8], password: Option<&str>) -> CvkResult<PKey<Private>> {
    load_private_key_inner(data, password)
        .map_err(|source| CvkOperationError::from_source(CvkOperation::PrivateKeyLoad, source))
}

fn load_private_key_inner(data: &[u8], password: Option<&str>) -> InternalResult<PKey<Private>> {
    let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    if data.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----") {
        let key = ssh_key::PrivateKey::from_openssh(data)?;
        let key = if key.is_encrypted() {
            key.decrypt(password.ok_or("需要提供私钥密码")?)?
        } else {
            key
        };
        let KeypairData::Rsa(rsa) = key.key_data() else {
            return Err("不支持的 OpenSSH 私钥算法".into());
        };
        let number = |n: &ssh_key::Mpint| -> InternalResult<BigNum> {
            Ok(BigNum::from_slice(
                n.as_positive_bytes().ok_or("RSA 私钥无效")?,
            )?)
        };
        let n = number(&rsa.public.n)?;
        let e = number(&rsa.public.e)?;
        let d = number(&rsa.private.d)?;
        let p = number(&rsa.private.p)?;
        let q = number(&rsa.private.q)?;
        let iqmp = number(&rsa.private.iqmp)?;
        let mut context = BigNumContext::new()?;
        let one = BigNum::from_u32(1)?;
        let mut p_minus_one = BigNum::new()?;
        let mut q_minus_one = BigNum::new()?;
        p_minus_one.checked_sub(&p, &one)?;
        q_minus_one.checked_sub(&q, &one)?;
        let mut dp = BigNum::new()?;
        let mut dq = BigNum::new()?;
        dp.nnmod(&d, &p_minus_one, &mut context)?;
        dq.nnmod(&d, &q_minus_one, &mut context)?;
        let key = Rsa::from_private_components(n, e, d, p, q, dp, dq, iqmp)?;
        if !key.check_key()? {
            return Err("RSA 私钥无效".into());
        }
        return Ok(PKey::from_rsa(key)?);
    }
    let password_requested = std::cell::Cell::new(false);
    let key = PKey::private_key_from_pem_callback(data, |buffer| {
        password_requested.set(true);
        let password = password.unwrap_or_default().as_bytes();
        if password.len() > buffer.len() {
            return Err(openssl::error::ErrorStack::get());
        }
        buffer[..password.len()].copy_from_slice(password);
        Ok(password.len())
    })?;
    if password.is_some() && !password_requested.get() {
        return Err("私钥未加密，不需要密码".into());
    }
    Ok(key)
}

#[cfg(test)]
mod password_detection_tests {
    use super::*;
    use openssl::symm::Cipher;

    #[test]
    fn detects_password_requirement_and_rejects_invalid_data() {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let plain = key.private_key_to_pem_pkcs8().unwrap();
        let encrypted = key
            .private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), b"test")
            .unwrap();
        let traditional = key
            .rsa()
            .unwrap()
            .private_key_to_pem_passphrase(Cipher::aes_256_cbc(), b"test")
            .unwrap();
        assert!(!private_key_requires_password(&plain).unwrap());
        assert!(private_key_requires_password(&encrypted).unwrap());
        assert!(private_key_requires_password(&traditional).unwrap());
        assert!(private_key_requires_password(b"invalid private key").is_err());
    }
}
