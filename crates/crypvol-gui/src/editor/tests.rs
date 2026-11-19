use super::{Editor, Message, protection, unlock};
use crate::{appearance::Feedback, cvk::Document};
use crypvol_core::crypto::{KeyProtection, KeyWrapAlgorithm};

fn saved_editor() -> (tempfile::TempDir, Editor) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("key.cvk");
    Document::new().unwrap().save(&path, None).unwrap();
    let editor = Editor::load(path).unwrap();
    (directory, editor)
}

#[test]
fn unchanged_values_and_failed_operations_do_not_mark_document_dirty() {
    let (_directory, mut editor) = saved_editor();
    for message in [
        Message::Label(String::new()),
        Message::Generator("CrypVol GUI".into()),
        Message::ToggleDetails,
        Message::Protection(protection::Message::Mode(KeyProtection::Plain)),
        Message::Protection(protection::Message::Algorithm(KeyWrapAlgorithm::None)),
        Message::Protection(protection::Message::Remove(0)),
    ] {
        editor.update(message);
        assert!(!editor.dirty);
    }
    assert!(matches!(editor.feedback, Feedback::Error(_)));
    editor.update(Message::Label("工作密钥".into()));
    assert!(editor.dirty);
    assert!(matches!(editor.feedback, Feedback::None));
    assert!(editor.title().starts_with("* key.cvk"));
}

#[test]
fn password_unlock_can_retry_and_save_after_editing() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("password.cvk");
    let mut document = Document::new().unwrap();
    document.set_protection(KeyProtection::Password);
    document
        .set_password_algorithm(KeyWrapAlgorithm::PasswordPbkdf2Sha256)
        .unwrap();
    document.save(&path, Some("test password")).unwrap();
    let mut editor = Editor::load(path.clone()).unwrap();
    editor.update(Message::Credentials(unlock::Message::Password(
        "wrong password".into(),
    )));
    editor.update(Message::Credentials(unlock::Message::Submit));
    assert!(editor.document.is_none());
    assert!(!editor.credentials.can_unlock());
    assert!(!editor.dirty);
    editor.update(Message::Credentials(unlock::Message::Password(
        "test password".into(),
    )));
    editor.update(Message::Credentials(unlock::Message::Submit));
    assert!(editor.document.is_some());
    editor.update(Message::Label("更新名称".into()));
    editor.update(Message::Save);
    assert!(editor.dirty);
    assert!(matches!(editor.feedback, Feedback::Error(_)));
    editor.update(Message::Protection(protection::Message::Password(
        "new password".into(),
    )));
    editor.update(Message::Save);
    assert!(!editor.dirty);
    let preview = Document::inspect(path).unwrap();
    let reopened = Document::open(&preview, Some("new password"), None, None).unwrap();
    assert_eq!(reopened.header.label.as_deref(), Some("更新名称"));
    assert_eq!(reopened.payload.cek, document.payload.cek);
}

#[test]
fn changing_password_algorithm_rejects_incompatible_mode_without_mutation() {
    let (_directory, mut editor) = saved_editor();
    editor.update(Message::Protection(protection::Message::Algorithm(
        KeyWrapAlgorithm::EcdhP256,
    )));
    assert!(!editor.dirty);
    assert_eq!(
        editor.document.as_ref().unwrap().header.key_wrap_algorithm,
        KeyWrapAlgorithm::None
    );
    assert!(matches!(editor.feedback, Feedback::Error(_)));
}
