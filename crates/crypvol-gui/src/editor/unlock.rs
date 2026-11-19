use crate::appearance::{Feedback, action, field, input};
use crate::cvk::{Document, Preview};
use crypvol_core::crypto::{KeyProtection, private_key_requires_password};
use iced::{
    Element, Fill,
    widget::{Id, column, text},
};
use std::path::PathBuf;
pub struct Credentials {
    password: String,
    private: Option<PathBuf>,
    passphrase: String,
    needs_password: bool,
    feedback: Feedback,
    input_id: Id,
}
impl Default for Credentials {
    fn default() -> Self {
        Self {
            password: String::new(),
            private: None,
            passphrase: String::new(),
            needs_password: false,
            feedback: Feedback::None,
            input_id: Id::unique(),
        }
    }
}
#[derive(Clone, Debug)]
pub enum Message {
    Password(String),
    PickPrivate,
    Passphrase(String),
    Submit,
}
impl Drop for Credentials {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
        self.passphrase.zeroize();
    }
}
impl Credentials {
    pub fn needs_password(&self) -> bool {
        self.needs_password
    }
    pub fn input_id(&self) -> Id {
        self.input_id.clone()
    }
    pub fn can_unlock(&self) -> bool {
        if self.needs_password {
            !self.passphrase.is_empty()
        } else {
            !self.password.is_empty() || self.private.is_some()
        }
    }
    pub fn set_error(&mut self, error: String) {
        self.feedback = Feedback::Error(error);
    }
    pub fn clear_password(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
        self.passphrase.zeroize();
    }
    pub fn password_view(&self) -> Element<'_, Message> {
        column![
            field(
                "私钥密码",
                input("输入私钥密码", &self.passphrase)
                    .id(self.input_id())
                    .secure(true)
                    .on_submit_maybe(self.can_unlock().then_some(Message::Submit))
                    .on_input(Message::Passphrase)
            ),
            self.feedback.view(),
        ]
        .spacing(12)
        .into()
    }
    /// 返回本次是否成功选择了私钥，取消选择不触发重试。
    pub fn update(&mut self, message: Message) -> bool {
        match message {
            Message::Password(value) => {
                use zeroize::Zeroize;
                self.password.zeroize();
                self.password = value;
                self.feedback = Feedback::None;
            }
            Message::Passphrase(value) => {
                use zeroize::Zeroize;
                self.passphrase.zeroize();
                self.passphrase = value;
                self.feedback = Feedback::None;
            }
            Message::Submit => {}
            Message::PickPrivate => {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    use zeroize::Zeroize;
                    self.passphrase.zeroize();
                    self.private = None;
                    self.needs_password = false;
                    self.feedback = Feedback::None;
                    match std::fs::read(&path)
                        .map(zeroize::Zeroizing::new)
                        .map_err(|error| error.to_string())
                        .and_then(|data| {
                            private_key_requires_password(&data).map_err(|error| error.to_string())
                        }) {
                        Ok(needs_password) => {
                            self.private = Some(path);
                            self.needs_password = needs_password;
                            return true;
                        }
                        Err(error) => self.set_error(error),
                    }
                }
            }
        }
        false
    }
    pub fn open(&self, preview: &Preview) -> Result<Document, String> {
        Document::open(
            preview,
            Some(&self.password),
            self.private.as_deref(),
            (!self.passphrase.is_empty()).then_some(self.passphrase.as_str()),
        )
    }
    pub fn view(&self, preview: &Preview) -> Element<'_, Message> {
        match preview.header.key_protection {
            KeyProtection::Plain => text("无需解锁").into(),
            KeyProtection::Password => column![
                field(
                    "解锁密码",
                    input("输入密钥密码", &self.password)
                        .id(self.input_id())
                        .secure(true)
                        .on_submit_maybe(self.can_unlock().then_some(Message::Submit))
                        .on_input(Message::Password)
                ),
                self.feedback.view(),
            ]
            .spacing(12)
            .into(),
            KeyProtection::PublicKey => column![
                action("选择解锁私钥…")
                    .width(Fill)
                    .on_press(Message::PickPrivate),
                self.feedback.view(),
            ]
            .spacing(12)
            .into(),
        }
    }
}
