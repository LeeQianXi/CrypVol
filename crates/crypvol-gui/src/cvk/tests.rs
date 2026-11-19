use super::Document;
use crypvol_core::crypto::KeyProtection;

#[test]
fn changing_protection_preserves_cek_and_rejects_invalid_save() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("key.cvk");
    let mut document = Document::new().unwrap();
    let original = zeroize::Zeroizing::new(document.payload.cek);
    document.save(&path, None).unwrap();
    document.set_protection(KeyProtection::Password);
    assert!(document.save(&path, None).is_err());
    document.save(&path, Some("test password")).unwrap();
    let preview = Document::inspect(&path).unwrap();
    assert!(Document::open(&preview, Some("wrong"), None, None).is_err());
    let reopened = Document::open(&preview, Some("test password"), None, None).unwrap();
    assert_eq!(reopened.payload.cek, *original);
    document.set_protection(KeyProtection::PublicKey);
    assert!(document.save(&path, None).is_err());
    document.set_protection(KeyProtection::Plain);
    document.save(&path, None).unwrap();
    assert_eq!(
        Document::open(&Document::inspect(path).unwrap(), None, None, None)
            .unwrap()
            .payload
            .cek,
        *original
    );
}

#[test]
fn recipient_import_is_atomic_and_preserves_existing_state() {
    let directory = tempfile::tempdir().unwrap();
    let public = directory.path().join("alice.pub");
    // 固定的测试用 RSA 公钥，仅用于验证导入及回滚，不执行加密。
    std::fs::write(
        &public,
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAAwEAAQ== alice",
    )
    .unwrap();
    let missing = directory.path().join("missing.pub");
    let mut document = Document::new().unwrap();
    document.set_protection(KeyProtection::PublicKey);
    document.header.key_wrap_algorithm = crypvol_core::crypto::KeyWrapAlgorithm::EcdhP384;
    assert!(document.add_recipients(&[public.clone(), missing]).is_err());
    assert!(document.payload.recipient_keys.is_empty());
    assert_eq!(
        document.header.key_wrap_algorithm,
        crypvol_core::crypto::KeyWrapAlgorithm::EcdhP384
    );
    assert!(
        document
            .add_recipients(std::slice::from_ref(&public))
            .unwrap()
    );
    let recipients = document.payload.recipient_keys.clone();
    assert!(document.add_recipients(&[public]).is_err());
    assert_eq!(document.payload.recipient_keys, recipients);
    assert!(!document.add_recipients(&[]).unwrap());
}

#[test]
fn invalid_metadata_never_replaces_existing_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("key.cvk");
    let mut document = Document::new().unwrap();
    document.save(&path, None).unwrap();
    let original = std::fs::read(&path).unwrap();
    document.header.created_at = Some("invalid date".into());
    assert!(document.validate_save(None).is_err());
    assert!(document.save(&path, None).is_err());
    assert_eq!(std::fs::read(path).unwrap(), original);
}
