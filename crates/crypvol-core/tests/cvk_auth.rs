mod support;

use base64::Engine;
use crypvol_core::crypto::{
    CvkEnvelope, CvkError, CvkOperation, CvkOperationError, CvkPayload, KeyProtection,
};
use support::cvk;

#[test]
fn password_documents_round_trip_and_reject_wrong_password() {
    use crypvol_core::crypto::{CvkHeader, CvkPayload, KeyWrapAlgorithm, encode, unlock};

    for algorithm in [
        KeyWrapAlgorithm::PasswordPbkdf2Sha256,
        KeyWrapAlgorithm::PasswordArgon2Id,
    ] {
        let header = CvkHeader {
            version: 1,
            key_protection: KeyProtection::Password,
            key_wrap_algorithm: algorithm,
            label: None,
            description: None,
            comment: None,
            created_at: None,
            generator: None,
        };
        let payload = CvkPayload {
            cek: [42; 32],
            recipient_keys: Vec::new(),
        };
        let bytes = encode(&header, &payload, Some("correct")).unwrap();
        let envelope = CvkEnvelope::parse(&bytes).unwrap();
        assert_eq!(unlock(&envelope, Some("correct")).unwrap().cek, [42; 32]);
        assert!(unlock(&envelope, Some("incorrect")).is_err());
    }
}

#[test]
fn core_preserves_whitespace_passwords() {
    use crypvol_core::crypto::{CvkHeader, KeyWrapAlgorithm, encode, unlock};

    let header = CvkHeader {
        version: 1,
        key_protection: KeyProtection::Password,
        key_wrap_algorithm: KeyWrapAlgorithm::PasswordPbkdf2Sha256,
        label: None,
        description: None,
        comment: None,
        created_at: None,
        generator: None,
    };
    let payload = CvkPayload {
        cek: [42; 32],
        recipient_keys: Vec::new(),
    };
    let bytes = encode(&header, &payload, Some("   ")).unwrap();
    let envelope = CvkEnvelope::parse(&bytes).unwrap();
    assert_eq!(unlock(&envelope, Some("   ")).unwrap().cek, [42; 32]);
}

#[test]
fn encoding_rejects_invalid_header_configuration() {
    use crypvol_core::crypto::{CvkHeader, KeyWrapAlgorithm, encode};

    let mut header = CvkHeader {
        version: 0,
        key_protection: KeyProtection::Plain,
        key_wrap_algorithm: KeyWrapAlgorithm::None,
        label: None,
        description: None,
        comment: None,
        created_at: None,
        generator: None,
    };
    let payload = CvkPayload {
        cek: [42; 32],
        recipient_keys: Vec::new(),
    };
    assert!(matches!(
        encode(&header, &payload, None),
        Err(CvkOperationError::Format(CvkError::UnsupportedVersion(0)))
    ));
    header.version = 1;
    header.key_wrap_algorithm = KeyWrapAlgorithm::PasswordPbkdf2Sha256;
    assert!(matches!(
        encode(&header, &payload, Some("password")),
        Err(CvkOperationError::Format(CvkError::IncompatibleProtection))
    ));
    header.key_protection = KeyProtection::Plain;
    header.key_wrap_algorithm = KeyWrapAlgorithm::None;
    header.created_at = Some("9999-12-31T23:59:59-14:00".into());
    assert!(matches!(
        encode(&header, &payload, None),
        Err(CvkOperationError::Format(CvkError::InvalidHeader))
    ));
}

#[test]
fn operation_errors_identify_the_failed_stage() {
    use crypvol_core::crypto::{CvkHeader, KeyWrapAlgorithm, encode, unlock};

    let header = CvkHeader {
        version: 1,
        key_protection: KeyProtection::Password,
        key_wrap_algorithm: KeyWrapAlgorithm::PasswordPbkdf2Sha256,
        label: None,
        description: None,
        comment: None,
        created_at: None,
        generator: None,
    };
    let payload = CvkPayload {
        cek: [42; 32],
        recipient_keys: Vec::new(),
    };
    let bytes = encode(&header, &payload, Some("correct")).unwrap();
    let envelope = CvkEnvelope::parse(&bytes).unwrap();
    assert_eq!(
        unlock(&envelope, Some("wrong")).err().unwrap().operation(),
        Some(CvkOperation::PasswordUnlock)
    );
}

#[test]
fn password_unlock_rejects_wrong_marker_and_truncated_body() {
    use crypvol_core::crypto::unlock;

    for (algorithm, marker) in [("PasswordPbkdf2Sha256", 1_u8), ("PasswordArgon2Id", 2)] {
        let header = format!(
            r#"{{"version":1,"keyProtection":"Password","keyWrapAlgorithm":"{algorithm}"}}"#
        );
        for body in [vec![marker], vec![0; 45]] {
            let bytes = cvk(header.as_bytes(), &body);
            let envelope = CvkEnvelope::parse(&bytes).unwrap();
            assert!(unlock(&envelope, Some("correct")).is_err());
        }
    }
    let header = br#"{"version":1,"keyProtection":"PublicKey","keyWrapAlgorithm":"RsaOaepSha256"}"#;
    let bytes = cvk(header, b"{}");
    let envelope = CvkEnvelope::parse(&bytes).unwrap();
    assert!(unlock(&envelope, None).is_err());
}

#[test]
fn password_authentication_rejects_rehashed_tampering() {
    use crypvol_core::crypto::{CvkHeader, KeyWrapAlgorithm, encode, unlock};

    let header = CvkHeader {
        version: 1,
        key_protection: KeyProtection::Password,
        key_wrap_algorithm: KeyWrapAlgorithm::PasswordPbkdf2Sha256,
        label: Some("original".into()),
        description: None,
        comment: None,
        created_at: None,
        generator: None,
    };
    let payload = CvkPayload {
        cek: [42; 32],
        recipient_keys: Vec::new(),
    };
    let original = encode(&header, &payload, Some("correct")).unwrap();
    let envelope = CvkEnvelope::parse(&original).unwrap();
    let mut body = envelope.key_body().to_vec();
    let end = body.len() - 1;
    body[end] ^= 1;
    let corrupted = cvk(envelope.header_bytes(), &body);
    let corrupted_envelope = CvkEnvelope::parse(&corrupted).unwrap();
    assert!(unlock(&corrupted_envelope, Some("correct")).is_err());

    let changed_header = std::str::from_utf8(envelope.header_bytes())
        .unwrap()
        .replace("original", "modified");
    let corrupted = cvk(changed_header.as_bytes(), envelope.key_body());
    let corrupted_envelope = CvkEnvelope::parse(&corrupted).unwrap();
    assert!(unlock(&corrupted_envelope, Some("correct")).is_err());
}

#[test]
fn password_unlock_rejects_reencoded_header() {
    use crypvol_core::crypto::{CvkHeader, KeyWrapAlgorithm, encode, unlock};

    let header = CvkHeader {
        version: 1,
        key_protection: KeyProtection::Password,
        key_wrap_algorithm: KeyWrapAlgorithm::PasswordPbkdf2Sha256,
        label: None,
        description: None,
        comment: None,
        created_at: Some("2026-11-16T17:40:07.1234567+00:00".into()),
        generator: None,
    };
    let payload = CvkPayload {
        cek: [42; 32],
        recipient_keys: Vec::new(),
    };
    let original = encode(&header, &payload, Some("correct")).unwrap();
    let envelope = CvkEnvelope::parse(&original).unwrap();
    let modified = std::str::from_utf8(envelope.header_bytes())
        .unwrap()
        .replace("1234567+00:00", "1234567000000000Z");
    let with_bom = [b"\xef\xbb\xbf".as_slice(), modified.as_bytes()].concat();
    let bytes = cvk(&with_bom, envelope.key_body());
    let envelope = CvkEnvelope::parse(&bytes).unwrap();
    assert!(unlock(&envelope, Some("correct")).is_err());
    let reordered = serde_json::to_vec(
        &serde_json::from_slice::<serde_json::Value>(modified.as_bytes()).unwrap(),
    )
    .unwrap();
    let bytes = cvk(&reordered, envelope.key_body());
    let envelope = CvkEnvelope::parse(&bytes).unwrap();
    assert!(unlock(&envelope, Some("correct")).is_err());
}

#[test]
fn public_key_authentication_rejects_rehashed_tampering() {
    use crypvol_core::crypto::{
        CvkHeader, KeyWrapAlgorithm, encode, load_public_key, unlock_with_private_key,
    };
    use openssl::{
        ec::{EcGroup, EcKey},
        nid::Nid,
        pkey::PKey,
        rsa::Rsa,
    };

    let rsa = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    for (algorithm, key) in [
        (KeyWrapAlgorithm::RsaOaepSha256, rsa),
        (KeyWrapAlgorithm::EcdhP256, ec),
    ] {
        let header = CvkHeader {
            version: 1,
            key_protection: KeyProtection::PublicKey,
            key_wrap_algorithm: algorithm,
            label: None,
            description: None,
            comment: None,
            created_at: None,
            generator: None,
        };
        let recipient = load_public_key(&key.public_key_to_pem().unwrap(), "alice").unwrap();
        let payload = CvkPayload {
            cek: [42; 32],
            recipient_keys: vec![recipient],
        };
        let bytes = encode(&header, &payload, None).unwrap();
        let envelope = CvkEnvelope::parse(&bytes).unwrap();
        assert_eq!(
            unlock_with_private_key(&envelope, &key).unwrap().cek,
            [42; 32]
        );
        let mut body: serde_json::Value = serde_json::from_slice(envelope.key_body()).unwrap();
        let mut invalid = body.clone();
        invalid["recipients"][0] = serde_json::json!(["alice", "invalid", null]);
        let invalid = cvk(
            envelope.header_bytes(),
            &serde_json::to_vec(&invalid).unwrap(),
        );
        assert!(unlock_with_private_key(&CvkEnvelope::parse(&invalid).unwrap(), &key).is_err());
        let mut invalid = body.clone();
        invalid["recipients"][0]["recipient"] = serde_json::json!(["alice", "RSA", "AQ==", null]);
        let invalid = cvk(
            envelope.header_bytes(),
            &serde_json::to_vec(&invalid).unwrap(),
        );
        assert!(unlock_with_private_key(&CvkEnvelope::parse(&invalid).unwrap(), &key).is_err());
        let recipients = body["recipients"].as_array_mut().unwrap();
        let mut unusable = recipients[0].clone();
        unusable["keyId"] = "unusable".into();
        unusable["recipient"]["keyId"] = "unusable".into();
        let damaged_field = if algorithm == KeyWrapAlgorithm::EcdhP256 {
            "nonce"
        } else {
            "wrappedKey"
        };
        unusable[damaged_field] = "!".into();
        recipients.insert(0, unusable);
        recipients.insert(0, serde_json::Value::Null);
        let mixed = cvk(envelope.header_bytes(), &serde_json::to_vec(&body).unwrap());
        let mixed = CvkEnvelope::parse(&mixed).unwrap();
        assert_eq!(unlock_with_private_key(&mixed, &key).unwrap().cek, [42; 32]);
        let tag_field = if algorithm == KeyWrapAlgorithm::EcdhP256 {
            "dataTag"
        } else {
            "tag"
        };
        let encoded_tag = body[tag_field].as_str().unwrap();
        let mut tag = base64::engine::general_purpose::STANDARD
            .decode(encoded_tag)
            .unwrap();
        tag[0] ^= 1;
        body[tag_field] =
            serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(tag));
        let corrupted = cvk(envelope.header_bytes(), &serde_json::to_vec(&body).unwrap());
        let envelope = CvkEnvelope::parse(&corrupted).unwrap();
        assert!(unlock_with_private_key(&envelope, &key).is_err());
    }
}
