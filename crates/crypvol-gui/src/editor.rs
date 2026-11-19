//! 一份 CVK 的选择、解锁、编辑和保存流水线。
mod protection;
mod unlock;
mod view;
use crate::appearance::Feedback;
use crate::cvk::{Document, Preview};
use std::path::PathBuf;

pub struct Editor {
    preview: Option<Preview>,
    document: Option<Document>,
    credentials: unlock::Credentials,
    protection: protection::Settings,
    dirty: bool,
    feedback: Feedback,
    details: bool,
}
#[derive(Clone, Debug)]
pub enum Message {
    Credentials(unlock::Message),
    Protection(protection::Message),
    Unlock,
    Label(String),
    Description(String),
    Comment(String),
    CreatedAt(String),
    Generator(String),
    Save,
    SaveAs,
    ToggleDetails,
    CancelUnlock,
}
impl Message {
    pub fn is_unlock(&self) -> bool {
        matches!(
            self,
            Self::Unlock | Self::Credentials(unlock::Message::Submit)
        )
    }
}
impl Editor {
    pub fn title(&self) -> String {
        let name = self
            .document
            .as_ref()
            .and_then(|document| document.source.as_ref())
            .or_else(|| self.preview.as_ref().map(|preview| &preview.source))
            .and_then(|path| path.file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "新密钥".into());
        format!("{}{} · CrypVol", if self.dirty { "* " } else { "" }, name)
    }
    pub fn focus_id(&self) -> Option<iced::widget::Id> {
        (self.document.is_none()).then(|| self.credentials.input_id())
    }
    pub fn needs_password(&self) -> bool {
        self.credentials.needs_password()
    }
    pub fn new(document: Document) -> Self {
        Self {
            preview: None,
            document: Some(document),
            credentials: Default::default(),
            protection: Default::default(),
            dirty: true,
            feedback: Feedback::None,
            details: false,
        }
    }
    pub fn load(path: PathBuf) -> Result<Self, String> {
        let preview = Document::inspect(path)?;
        let document =
            if preview.header.key_protection == crypvol_core::crypto::KeyProtection::Plain {
                Some(Document::open(&preview, None, None, None)?)
            } else {
                None
            };
        Ok(Self {
            preview: Some(preview),
            document,
            credentials: Default::default(),
            protection: Default::default(),
            dirty: false,
            feedback: Feedback::None,
            details: false,
        })
    }
    pub fn confirm_close(&self) -> bool {
        !self.dirty
            || rfd::MessageDialog::new()
                .set_title("未保存的修改")
                .set_description("放弃这份密钥的未保存修改？")
                .set_buttons(rfd::MessageButtons::YesNo)
                .show()
                == rfd::MessageDialogResult::Yes
    }
    pub fn update(&mut self, message: Message) {
        match message {
            Message::ToggleDetails => self.details = !self.details,
            Message::CancelUnlock => self.credentials = Default::default(),
            Message::Credentials(unlock::Message::Submit) => self.update(Message::Unlock),
            Message::Credentials(message) => {
                let picked = self.credentials.update(message);
                if picked && !self.credentials.needs_password() {
                    self.update(Message::Unlock);
                }
            }
            Message::Unlock if self.credentials.can_unlock() => {
                if let Some(preview) = &self.preview {
                    match self.credentials.open(preview) {
                        Ok(document) => {
                            self.document = Some(document);
                            self.credentials = Default::default();
                            self.feedback = Feedback::None;
                        }
                        Err(error) => {
                            self.credentials.clear_password();
                            self.credentials.set_error(error);
                        }
                    }
                }
            }
            Message::Unlock => {}
            Message::Save if self.dirty => self.save(false),
            Message::Save => {}
            Message::SaveAs => self.save(true),
            message => {
                if let Some(document) = &mut self.document {
                    let result = match message {
                        Message::Label(value) => {
                            Ok(replace_optional(&mut document.header.label, value))
                        }
                        Message::Description(value) => {
                            Ok(replace_optional(&mut document.header.description, value))
                        }
                        Message::Comment(value) => {
                            Ok(replace_optional(&mut document.header.comment, value))
                        }
                        Message::CreatedAt(value) => {
                            Ok(replace_optional(&mut document.header.created_at, value))
                        }
                        Message::Generator(value) => {
                            Ok(replace_optional(&mut document.header.generator, value))
                        }
                        Message::Protection(message) => self.protection.update(document, message),
                        _ => Ok(false),
                    };
                    match result {
                        Ok(true) => {
                            self.dirty = true;
                            self.feedback = Feedback::None;
                        }
                        Ok(false) => {}
                        Err(error) => self.feedback = Feedback::Error(error),
                    }
                }
            }
        }
    }
    fn save(&mut self, save_as: bool) {
        let Some(document) = &mut self.document else {
            return;
        };
        if let Err(error) = document.validate_save(self.protection.password()) {
            self.feedback = Feedback::Error(error);
            return;
        }
        let destination = if save_as || document.source.is_none() {
            rfd::FileDialog::new()
                .add_filter("CVK", &["cvk"])
                .set_file_name(
                    document
                        .source
                        .as_ref()
                        .and_then(|path| path.file_name())
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "key.cvk".into()),
                )
                .save_file()
        } else {
            document.source.clone()
        };
        let Some(destination) = destination else {
            return;
        };
        match document.save(destination, self.protection.password()) {
            Ok(()) => {
                self.dirty = false;
                self.feedback = Feedback::Success("已保存".into());
            }
            Err(error) => self.feedback = Feedback::Error(error),
        }
    }
}

#[cfg(test)]
mod tests;
fn replace_optional(target: &mut Option<String>, value: String) -> bool {
    let value = (!value.is_empty()).then_some(value);
    if *target == value {
        false
    } else {
        *target = value;
        true
    }
}
