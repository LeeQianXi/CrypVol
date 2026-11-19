mod support;

use crypvol_core::crypto::{CvkEnvelope, CvkError, CvkPayload, KeyProtection};
use support::cvk;

const PLAIN_HEADER: &[u8] = br#"{"version":1,"keyProtection":"Plain","keyWrapAlgorithm":"None"}"#;
const PAYLOAD: &[u8] =
    br#"{"cek":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","recipientKeys":[]}"#;

#[test]
fn parses_plain_cvk_with_bom_and_original_header_bytes() {
    let header = [b"\xef\xbb\xbf", PLAIN_HEADER].concat();
    let bytes = cvk(&header, PAYLOAD);
    let envelope = CvkEnvelope::parse(&bytes).unwrap();
    assert_eq!(envelope.header().key_protection, KeyProtection::Plain);
    assert_eq!(envelope.header_bytes(), header);
    assert_eq!(envelope.plain_payload().unwrap().cek, [1; 32]);
}

#[test]
fn checks_cvk_integrity_across_encoding_chunks_without_unlocking() {
    let header =
        br#"{"version":1,"keyProtection":"Password","keyWrapAlgorithm":"PasswordArgon2Id"}"#;
    let body = vec![255; 6145];
    let mut bytes = cvk(header, &body);
    let envelope = CvkEnvelope::parse(&bytes).unwrap();
    assert_eq!(envelope.key_body(), body);
    assert_eq!(
        envelope.plain_payload().err(),
        Some(CvkError::ProtectedPayload)
    );

    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert_eq!(
        CvkEnvelope::parse(&bytes).err(),
        Some(CvkError::DigestMismatch)
    );
    assert_eq!(
        CvkEnvelope::parse(&bytes[..last]).err(),
        Some(CvkError::Truncated)
    );
    bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        CvkEnvelope::parse(&bytes).err(),
        Some(CvkError::InvalidLength)
    );
}

#[test]
fn rejects_invalid_container_lengths_and_magic() {
    let valid = cvk(PLAIN_HEADER, PAYLOAD);
    for length in [0, 4, 15] {
        assert_eq!(
            CvkEnvelope::parse(&valid[..length]).err(),
            Some(CvkError::Truncated)
        );
    }
    let mut invalid = valid.clone();
    invalid[0] ^= 1;
    assert_eq!(
        CvkEnvelope::parse(&invalid).err(),
        Some(CvkError::InvalidMagic)
    );

    for (offset, value) in [
        (4, 0_u32),
        (4, 1024 * 1024 + 1),
        (8, 0),
        (8, 256 * 1024 * 1024 + 1),
        (12, 0),
        (12, 31),
        (12, 33),
    ] {
        let mut invalid = valid.clone();
        invalid[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        assert_eq!(
            CvkEnvelope::parse(&invalid).err(),
            Some(CvkError::InvalidLength)
        );
    }
    let mut appended = valid.clone();
    appended.push(0);
    assert_eq!(
        CvkEnvelope::parse(&appended).err(),
        Some(CvkError::InvalidLength)
    );
    assert_eq!(
        CvkEnvelope::parse(&valid[..valid.len() - 1]).err(),
        Some(CvkError::Truncated)
    );
}

#[test]
fn rejects_invalid_header_and_payload_shapes() {
    for header in [
        br#"null"#.as_slice(),
        br#"{"version":1,"keyProtection":"Plain"}"#,
        br#"{"version":1,"keyProtection":"Plain","keyWrapAlgorithm":"None","label":5}"#,
        br#"{"version":1,"keyProtection":"plain","keyWrapAlgorithm":"None"}"#,
        br#"{"version":65536,"keyProtection":"Plain","keyWrapAlgorithm":"None"}"#,
        br#"{"version":1,"keyProtection":"Plain","keyWrapAlgorithm":"None",}"#,
    ] {
        assert_eq!(
            CvkEnvelope::parse(&cvk(header, PAYLOAD)).err(),
            Some(CvkError::InvalidHeader)
        );
    }
    let cek = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    let invalid_payloads = [
        format!(r#"{{"cek":"{cek}"}}"#),
        format!(r#"{{"cek":"{cek}","cek":"{cek}","recipientKeys":[]}}"#),
        format!(r#"{{"cek":"{cek}","recipientKeys":[],"unknown":1}}"#),
        format!(
            r#"{{"cek":"{cek}","recipientKeys":[{{"keyId":"","algorithm":"RSA","publicKey":"AQ=="}}]}}"#
        ),
        format!(
            r#"{{"cek":"{cek}","recipientKeys":[{{"keyId":"alice","algorithm":"RSA","publicKey":""}}]}}"#
        ),
        format!(
            r#"{{"cek":"{cek}","recipientKeys":[{{"keyId":"alice","algorithm":"OTHER","publicKey":"AQ=="}}]}}"#
        ),
        format!(
            r#"{{"cek":"{cek}","recipientKeys":[{{"keyId":"alice","algorithm":"RSA","publicKey":"!"}}]}}"#
        ),
    ];
    for payload in invalid_payloads {
        assert!(CvkPayload::parse(payload.as_bytes()).is_err());
    }
}

#[test]
fn rejects_duplicate_unknown_or_incompatible_cvk_fields() {
    for header in [
        br#"{"version":1,"version":1,"keyProtection":"Plain","keyWrapAlgorithm":"None"}"#.as_slice(),
        br#"{"version":1,"keyProtection":"Plain","keyWrapAlgorithm":"None","extra":null}"#,
        br#"[1,"Plain","None",null,null,null,null,null]"#,
        br#"{"version":1,"keyProtection":{"Plain":null},"keyWrapAlgorithm":"None"}"#,
        br#"{"version":1,"keyProtection":"Plain","keyWrapAlgorithm":"None","createdAt":"yesterday"}"#,
        br#"{"version":1,"keyProtection":"Plain","keyWrapAlgorithm":"None","createdAt":"0000-01-01T00:00:00Z"}"#,
        br#"{"version":1,"keyProtection":"Plain","keyWrapAlgorithm":"None","createdAt":"0001-01-01T00:00:00+14:00"}"#,
        br#"{"version":1,"keyProtection":"Plain","keyWrapAlgorithm":"None","createdAt":"9999-12-31T23:59:59-14:00"}"#,
        br#"{"version":1,"keyProtection":"Plain","keyWrapAlgorithm":"None","createdAt":"2024-12-31T23:59:60Z"}"#,
        br#"{"version":1,"keyProtection":"Plain","keyWrapAlgorithm":"None","createdAt":"2026-11-17t01:02:03z"}"#,
        br#"{"version":1,"keyProtection":"Plain","keyWrapAlgorithm":"None","createdAt":"2026-01-01T00:00:00.12345678901234567Z"}"#,
        br#"{"version":1,"keyProtection":"Plain","keyWrapAlgorithm":"None","createdAt":"2026-01-01T00:00:00+14:01"}"#,
    ] {
        assert_eq!(CvkEnvelope::parse(&cvk(header, PAYLOAD)).err(), Some(CvkError::InvalidHeader));
    }
    let header = br#"{"version":1,"keyProtection":"Password","keyWrapAlgorithm":"None"}"#;
    assert_eq!(
        CvkEnvelope::parse(&cvk(header, PAYLOAD)).err(),
        Some(CvkError::IncompatibleProtection)
    );
    let header = br#"{"version":0,"keyProtection":"Plain","keyWrapAlgorithm":"None"}"#;
    assert_eq!(
        CvkEnvelope::parse(&cvk(header, PAYLOAD)).err(),
        Some(CvkError::UnsupportedVersion(0))
    );
}

#[test]
fn nonzero_header_versions_round_trip() {
    use crypvol_core::crypto::{CvkHeader, KeyWrapAlgorithm, encode};

    for version in [1, 2, u16::MAX] {
        let header = CvkHeader {
            version,
            key_protection: KeyProtection::Plain,
            key_wrap_algorithm: KeyWrapAlgorithm::None,
            label: None,
            description: None,
            comment: None,
            created_at: None,
            generator: None,
        };
        let payload = CvkPayload {
            cek: [0; 32],
            recipient_keys: Vec::new(),
        };
        let bytes = encode(&header, &payload, None).unwrap();
        let envelope = CvkEnvelope::parse(&bytes).unwrap();
        assert_eq!(envelope.header().version, version);
        assert_eq!(envelope.plain_payload().unwrap().cek, [0; 32]);
    }
}

#[test]
fn format_errors_have_actionable_messages() {
    for error in [
        CvkError::Truncated,
        CvkError::InvalidMagic,
        CvkError::InvalidLength,
        CvkError::DigestMismatch,
        CvkError::InvalidHeader,
        CvkError::UnsupportedVersion(0),
        CvkError::IncompatibleProtection,
        CvkError::ProtectedPayload,
        CvkError::InvalidPayload,
        CvkError::InvalidCek,
        CvkError::InvalidRecipient,
    ] {
        assert!(!error.to_string().trim().is_empty());
    }
}

#[test]
fn validates_cek_and_recipient_objects() {
    assert_eq!(
        CvkPayload::parse(br#"{"cek":"AA==","recipientKeys":[]}"#).err(),
        Some(CvkError::InvalidCek)
    );
    let cek = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    let recipient = r#"{"keyId":"alice","algorithm":"RSA","publicKey":"AQ=="}"#;
    let json = format!(r#"{{"cek":"{cek}","recipientKeys":[{recipient}]}}"#);
    assert_eq!(
        CvkPayload::parse(json.as_bytes()).unwrap().recipient_keys[0].key_id,
        "alice"
    );
    let repeated = format!(r#"{{"cek":"{cek}","recipientKeys":[{recipient},{recipient}]}}"#);
    assert_eq!(
        CvkPayload::parse(repeated.as_bytes()).err(),
        Some(CvkError::InvalidRecipient)
    );
    let array = format!(r#"{{"cek":"{cek}","recipientKeys":[["alice","RSA","AQ==",null]]}}"#);
    assert_eq!(
        CvkPayload::parse(array.as_bytes()).err(),
        Some(CvkError::InvalidRecipient)
    );

    let payload = serde_json::json!({
        "cek": format!(" {}\r\n", cek),
        "recipientKeys": [{"keyId":"alice", "algorithm":"RSA", "publicKey":" AQ==\t"}]
    });
    let parsed = CvkPayload::parse(&serde_json::to_vec(&payload).unwrap()).unwrap();
    assert_eq!(parsed.cek, [1; 32]);
    assert_eq!(parsed.recipient_keys[0].public_key, [1]);
}
