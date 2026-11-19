use crate::appearance::{action, card, field, hint, input};
use crate::cvk::Document;
use crypvol_core::crypto::{KeyProtection, KeyWrapAlgorithm, KeyWrapFamily, RecipientAlgorithm};
use iced::{
    Element, Fill,
    widget::{button, column, pick_list, row, text},
};
#[derive(Default)]
pub struct Settings {
    password: String,
}
impl Drop for Settings {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
    }
}
#[derive(Clone, Debug)]
pub enum Message {
    Mode(KeyProtection),
    Password(String),
    Algorithm(KeyWrapAlgorithm),
    Add,
    Remove(usize),
    Id(usize, String),
    Comment(usize, String),
}
impl Settings {
    pub fn password(&self) -> Option<&str> {
        (!self.password.is_empty()).then_some(self.password.as_str())
    }
    pub fn update(&mut self, document: &mut Document, message: Message) -> Result<bool, String> {
        let mut changed = false;
        match message {
            Message::Mode(mode) => {
                if mode != document.header.key_protection {
                    document.set_protection(mode);
                    use zeroize::Zeroize;
                    self.password.zeroize();
                    changed = true;
                }
            }
            Message::Password(value) => {
                changed = self.password != value;
                use zeroize::Zeroize;
                self.password.zeroize();
                self.password = value;
            }
            Message::Algorithm(algorithm) => {
                if algorithm == document.header.key_wrap_algorithm {
                    return Ok(false);
                }
                if algorithm.protection() != document.header.key_protection {
                    return Err("所选算法不适用于当前保护方式".into());
                }
                if document
                    .payload
                    .recipient_keys
                    .iter()
                    .any(|key| !compatible(algorithm, key.algorithm))
                {
                    return Err("所选算法与接收者公钥类型不匹配".into());
                }
                if document.header.key_protection == KeyProtection::Password {
                    document.set_password_algorithm(algorithm)?;
                } else {
                    document.header.key_wrap_algorithm = algorithm;
                }
                changed = true;
            }
            Message::Add => {
                if let Some(paths) = rfd::FileDialog::new().pick_files() {
                    changed = document.add_recipients(&paths)?;
                }
            }
            Message::Remove(index) => {
                document.remove_recipient(index)?;
                changed = true;
            }
            Message::Id(index, value) => {
                if let Some(key) = document.payload.recipient_keys.get_mut(index) {
                    changed = key.key_id != value;
                    key.key_id = value;
                }
            }
            Message::Comment(index, value) => {
                if let Some(key) = document.payload.recipient_keys.get_mut(index) {
                    let value = (!value.is_empty()).then_some(value);
                    changed = key.comment != value;
                    key.comment = value;
                }
            }
        }
        Ok(changed)
    }
    pub fn view<'a>(&'a self, document: &'a Document) -> Element<'a, Message> {
        let mode = document.header.key_protection;
        let choice = |label, value| {
            action(label)
                .width(Fill)
                .style(if mode == value {
                    button::primary
                } else {
                    button::secondary
                })
                .on_press(Message::Mode(value))
        };
        let options = row![
            choice("无保护", KeyProtection::Plain),
            choice("密码", KeyProtection::Password),
            choice("公钥", KeyProtection::PublicKey),
        ]
        .spacing(12);
        let body: Element<'a, Message> = match mode {
            KeyProtection::Plain => hint("保存后可直接读取此密钥。请选择适合的保护方式。").into(),
            KeyProtection::Password => column![
                field(
                    "保存密码",
                    input("输入保存密码", &self.password)
                        .secure(true)
                        .on_input(Message::Password)
                ),
                field(
                    "封装算法",
                    algorithms(
                        &[
                            KeyWrapAlgorithm::PasswordArgon2Id,
                            KeyWrapAlgorithm::PasswordPbkdf2Sha256
                        ],
                        document.header.key_wrap_algorithm
                    )
                ),
                hint("每次保存均使用此处填写的密码。"),
            ]
            .spacing(12)
            .into(),
            KeyProtection::PublicKey => {
                let list = document.payload.recipient_keys.iter().enumerate().fold(
                    column![].spacing(12),
                    |list, (index, key)| {
                        list.push(
                            card(
                                column![
                                    row![
                                        field(
                                            "接收者标识",
                                            input("接收者标识", &key.key_id)
                                                .on_input(move |value| Message::Id(index, value))
                                        ),
                                        action("移除")
                                            .style(button::danger)
                                            .on_press(Message::Remove(index))
                                    ]
                                    .spacing(12)
                                    .align_y(iced::Alignment::End),
                                    field(
                                        "注释",
                                        input("接收者注释", key.comment.as_deref().unwrap_or(""))
                                            .on_input(move |value| Message::Comment(index, value))
                                    ),
                                ]
                                .spacing(8),
                            )
                            .width(Fill),
                        )
                    },
                );
                let list = if document.payload.recipient_keys.is_empty() {
                    list.push(hint("尚未添加接收者，请选择公钥文件。"))
                } else {
                    list
                };
                column![
                    field(
                        "封装算法",
                        algorithms(
                            &[
                                KeyWrapAlgorithm::RsaOaepSha256,
                                KeyWrapAlgorithm::RsaOaepSha384,
                                KeyWrapAlgorithm::RsaOaepSha512,
                                KeyWrapAlgorithm::EcdhP256,
                                KeyWrapAlgorithm::EcdhP384,
                                KeyWrapAlgorithm::EcdhP521
                            ]
                            .into_iter()
                            .filter(|algorithm| {
                                document
                                    .payload
                                    .recipient_keys
                                    .iter()
                                    .all(|key| compatible(*algorithm, key.algorithm))
                            })
                            .collect::<Vec<_>>(),
                            document.header.key_wrap_algorithm
                        )
                    ),
                    list,
                    action("添加公钥…")
                        .style(button::secondary)
                        .on_press(Message::Add)
                ]
                .spacing(12)
                .into()
            }
        };
        column![text("保护方式").size(20), options, body]
            .spacing(16)
            .into()
    }
}
fn compatible(algorithm: KeyWrapAlgorithm, recipient: RecipientAlgorithm) -> bool {
    matches!(
        (algorithm.family(), recipient),
        (KeyWrapFamily::Rsa, RecipientAlgorithm::Rsa)
            | (KeyWrapFamily::Ecdh, RecipientAlgorithm::Ecdh)
    )
}
fn algorithms(
    values: &[KeyWrapAlgorithm],
    selected: KeyWrapAlgorithm,
) -> Element<'static, Message> {
    pick_list(
        values.iter().copied().map(Algorithm).collect::<Vec<_>>(),
        Some(Algorithm(selected)),
        |value| Message::Algorithm(value.0),
    )
    .width(Fill)
    .padding(12)
    .into()
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Algorithm(KeyWrapAlgorithm);

impl std::fmt::Display for Algorithm {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self.0 {
            KeyWrapAlgorithm::None => "无",
            KeyWrapAlgorithm::PasswordArgon2Id => "Argon2id",
            KeyWrapAlgorithm::PasswordPbkdf2Sha256 => "PBKDF2 · SHA-256",
            KeyWrapAlgorithm::RsaOaepSha256 => "RSA-OAEP · SHA-256",
            KeyWrapAlgorithm::RsaOaepSha384 => "RSA-OAEP · SHA-384",
            KeyWrapAlgorithm::RsaOaepSha512 => "RSA-OAEP · SHA-512",
            KeyWrapAlgorithm::EcdhP256 => "ECDH · P-256",
            KeyWrapAlgorithm::EcdhP384 => "ECDH · P-384",
            KeyWrapAlgorithm::EcdhP521 => "ECDH · P-521",
        })
    }
}
