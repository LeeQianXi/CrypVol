use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use crypvol_core::crypto::{
    CvkEnvelope, CvkHeader, CvkPayload, KeyProtection, KeyWrapAlgorithm, encode, load_private_key,
    load_public_key, random_cek, unlock, unlock_with_private_key, unlock_with_private_key_aad,
};
use crypvol_migrate::{legacy_header_bytes, unlock_password};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

pub struct Preview {
    pub source: PathBuf,
    pub header: CvkHeader,
}

/// 已解封的 CVK 编辑会话。CEK 从不进入界面状态或文本控件。
pub struct Document {
    pub source: Option<PathBuf>,
    pub header: CvkHeader,
    pub payload: CvkPayload,
}

impl Document {
    pub fn inspect(path: impl AsRef<Path>) -> Result<Preview, String> {
        let source = path.as_ref().to_owned();
        let bytes = Zeroizing::new(fs::read(&source).map_err(display)?);
        let envelope = CvkEnvelope::parse(&bytes).map_err(display)?;
        Ok(Preview {
            source,
            header: envelope.header().clone(),
        })
    }

    pub fn new() -> Result<Self, String> {
        Ok(Self {
            source: None,
            header: CvkHeader {
                version: 1,
                key_protection: KeyProtection::Plain,
                key_wrap_algorithm: KeyWrapAlgorithm::None,
                label: None,
                description: None,
                comment: None,
                created_at: None,
                generator: Some("CrypVol GUI".into()),
            },
            payload: CvkPayload {
                cek: random_cek().map_err(display)?,
                recipient_keys: Vec::new(),
            },
        })
    }

    /// 按原生规则解封，认证不通过时在相同加载阶段尝试旧版兼容规则。
    pub fn open(
        preview: &Preview,
        password: Option<&str>,
        private_key_path: Option<&Path>,
        private_key_password: Option<&str>,
    ) -> Result<Self, String> {
        let bytes = Zeroizing::new(fs::read(&preview.source).map_err(display)?);
        let envelope = CvkEnvelope::parse(&bytes).map_err(display)?;
        let header = envelope.header().clone();
        let payload = match header.key_protection {
            KeyProtection::Plain => envelope.plain_payload().map_err(display)?,
            KeyProtection::Password => unlock(&envelope, password)
                .or_else(|_| unlock_password(&envelope, password).map_err(display))
                .map_err(|_| "密码错误或 CVK 密钥体认证失败".to_owned())?,
            KeyProtection::PublicKey => {
                let path = private_key_path.ok_or("公钥保护 CVK 需要选择解封私钥")?;
                let private = Zeroizing::new(fs::read(path).map_err(display)?);
                let key = load_private_key(&private, private_key_password).map_err(display)?;
                unlock_with_private_key(&envelope, &key)
                    .map_err(display)
                    .or_else(|_| {
                        let aad = legacy_header_bytes(&header).map_err(display)?;
                        unlock_with_private_key_aad(&envelope, &key, &aad).map_err(display)
                    })
                    .map_err(|_| "私钥不匹配或 CVK 密钥体认证失败".to_owned())?
            }
        };
        Ok(Self {
            source: Some(preview.source.clone()),
            header,
            payload,
        })
    }

    pub fn set_protection(&mut self, protection: KeyProtection) {
        self.header.key_protection = protection;
        self.header.key_wrap_algorithm = match protection {
            KeyProtection::Plain => KeyWrapAlgorithm::None,
            KeyProtection::Password => KeyWrapAlgorithm::PasswordArgon2Id,
            KeyProtection::PublicKey => KeyWrapAlgorithm::RsaOaepSha256,
        };
        if protection != KeyProtection::PublicKey {
            self.payload.recipient_keys.clear();
        }
    }

    pub fn set_password_algorithm(&mut self, algorithm: KeyWrapAlgorithm) -> Result<(), String> {
        if !matches!(
            algorithm,
            KeyWrapAlgorithm::PasswordPbkdf2Sha256 | KeyWrapAlgorithm::PasswordArgon2Id
        ) {
            return Err("所选算法不能用于密码保护".into());
        }
        self.header.key_protection = KeyProtection::Password;
        self.header.key_wrap_algorithm = algorithm;
        self.payload.recipient_keys.clear();
        Ok(())
    }

    pub fn add_recipient(&mut self, path: impl AsRef<Path>) -> Result<(), String> {
        if self.header.key_protection != KeyProtection::PublicKey {
            return Err("请先切换到公钥保护模式".into());
        }
        let path = path.as_ref();
        let name = path
            .file_stem()
            .and_then(|name| name.to_str())
            .ok_or("公钥文件名无效")?;
        let recipient =
            load_public_key(&fs::read(path).map_err(display)?, name).map_err(display)?;
        if self
            .payload
            .recipient_keys
            .iter()
            .any(|existing| existing.key_id == recipient.key_id)
        {
            return Err(format!("接收者 KeyId 已存在：{}", recipient.key_id));
        }
        if self.payload.recipient_keys.is_empty() {
            self.header.key_wrap_algorithm = match recipient.algorithm {
                crypvol_core::crypto::RecipientAlgorithm::Rsa => KeyWrapAlgorithm::RsaOaepSha256,
                crypvol_core::crypto::RecipientAlgorithm::Ecdh => KeyWrapAlgorithm::EcdhP256,
            };
        } else {
            let compatible = matches!(
                (self.header.key_wrap_algorithm.family(), recipient.algorithm),
                (
                    crypvol_core::crypto::KeyWrapFamily::Rsa,
                    crypvol_core::crypto::RecipientAlgorithm::Rsa
                ) | (
                    crypvol_core::crypto::KeyWrapFamily::Ecdh,
                    crypvol_core::crypto::RecipientAlgorithm::Ecdh
                )
            );
            if !compatible {
                return Err("一个 CVK 只能包含同一类公钥接收者".into());
            }
        }
        self.payload.recipient_keys.push(recipient);
        Ok(())
    }

    /// 一次文件选择作为一次操作；任一公钥无效时恢复原接收者与算法。
    pub fn add_recipients(&mut self, paths: &[PathBuf]) -> Result<bool, String> {
        let count = self.payload.recipient_keys.len();
        let algorithm = self.header.key_wrap_algorithm;
        for path in paths {
            if let Err(error) = self.add_recipient(path) {
                self.payload.recipient_keys.truncate(count);
                self.header.key_wrap_algorithm = algorithm;
                return Err(error);
            }
        }
        Ok(self.payload.recipient_keys.len() != count)
    }

    pub fn remove_recipient(&mut self, index: usize) -> Result<(), String> {
        if index >= self.payload.recipient_keys.len() {
            return Err("接收者不存在".into());
        }
        self.payload.recipient_keys.remove(index);
        Ok(())
    }

    pub fn save(
        &mut self,
        destination: impl AsRef<Path>,
        password: Option<&str>,
    ) -> Result<(), String> {
        self.validate_save(password)?;
        let destination = destination.as_ref();
        let password = (self.header.key_protection == KeyProtection::Password)
            .then_some(password)
            .flatten();
        let data = Zeroizing::new(encode(&self.header, &self.payload, password).map_err(display)?);
        atomic_replace(destination, &data)?;
        self.source = Some(destination.to_owned());
        Ok(())
    }

    pub fn validate_save(&self, password: Option<&str>) -> Result<(), String> {
        self.header.validate().map_err(display)?;
        if self.header.key_protection == KeyProtection::PublicKey
            && self.payload.recipient_keys.is_empty()
        {
            return Err("公钥保护 CVK 至少需要一个接收者".into());
        }
        if self.header.key_protection == KeyProtection::Password
            && password.is_none_or(str::is_empty)
        {
            return Err("密码保护 CVK 需要填写保存密码".into());
        }
        Ok(())
    }
}

fn atomic_replace(path: &Path, data: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = NamedTempFile::new_in(parent).map_err(display)?;
    temporary.write_all(data).map_err(display)?;
    temporary.as_file().sync_all().map_err(display)?;
    temporary
        .persist(path)
        .map_err(|error| display(error.error))?;
    Ok(())
}

fn display(error: impl std::fmt::Display) -> String {
    error.to_string()
}
