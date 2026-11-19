mod support;

use crypvol_core::crypto::{
    CvkEnvelope, CvkHeader, CvkPayload, KeyWrapAlgorithm, encode, load_public_key,
    unlock_with_private_key,
};
use openssl::{
    ec::{EcGroup, EcKey},
    encrypt::Encrypter,
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    rsa::{Padding, Rsa},
};
use support::cvk;

#[test]
fn public_key_bodies_reject_malformed_fields_and_wrong_private_keys() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let rsa = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let wrong_rsa = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let ec = PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
    )
    .unwrap();
    let wrong_ec = PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::SECP384R1).unwrap()).unwrap(),
    )
    .unwrap();

    for (algorithm, key, wrong) in [
        (KeyWrapAlgorithm::RsaOaepSha256, &rsa, &wrong_rsa),
        (KeyWrapAlgorithm::EcdhP256, &ec, &wrong_ec),
    ] {
        let header = CvkHeader {
            version: 1,
            key_protection: algorithm.protection(),
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
        assert!(unlock_with_private_key(&envelope, wrong).is_err());
        let body: serde_json::Value = serde_json::from_slice(envelope.key_body()).unwrap();
        let mut whitespace = body.clone();
        let nonce_field = if algorithm == KeyWrapAlgorithm::EcdhP256 {
            "dataNonce"
        } else {
            "nonce"
        };
        let encoded = whitespace[nonce_field].as_str().unwrap().to_owned();
        whitespace[nonce_field] = format!(" {encoded}\n").into();
        let encoded = whitespace["recipients"][0]["recipient"]["publicKey"]
            .as_str()
            .unwrap()
            .to_owned();
        whitespace["recipients"][0]["recipient"]["publicKey"] = format!("{encoded}\r\n").into();
        let whitespace = cvk(
            envelope.header_bytes(),
            &serde_json::to_vec(&whitespace).unwrap(),
        );
        let whitespace = CvkEnvelope::parse(&whitespace).unwrap();
        assert_eq!(
            unlock_with_private_key(&whitespace, key).unwrap().cek,
            [42; 32]
        );
        let mut malformed = Vec::new();

        let mut missing = body.clone();
        missing.as_object_mut().unwrap().remove("ciphertext");
        malformed.push(missing);
        let mut unknown = body.clone();
        unknown["unknown"] = true.into();
        malformed.push(unknown);
        let mut not_string = body.clone();
        not_string["ciphertext"] = 42.into();
        malformed.push(not_string);
        let mut invalid_base64 = body.clone();
        invalid_base64["ciphertext"] = "!".into();
        malformed.push(invalid_base64);
        let mut short_nonce = body.clone();
        short_nonce[if algorithm == KeyWrapAlgorithm::EcdhP256 {
            "dataNonce"
        } else {
            "nonce"
        }] = "AQ==".into();
        malformed.push(short_nonce);
        if algorithm == KeyWrapAlgorithm::EcdhP256 {
            let mut short_recipient_nonce = body.clone();
            short_recipient_nonce["recipients"][0]["nonce"] = "AQ==".into();
            malformed.push(short_recipient_nonce);
            let mut wrong_ephemeral_curve = body.clone();
            wrong_ephemeral_curve["recipients"][0]["ephemeralPublicKey"] = STANDARD
                .encode(wrong_ec.public_key_to_der().unwrap())
                .into();
            malformed.push(wrong_ephemeral_curve);
        } else {
            let mut invalid_wrapped_key = body.clone();
            invalid_wrapped_key["recipients"][0]["wrappedKey"] = "!".into();
            malformed.push(invalid_wrapped_key);
        }
        let mut empty = body.clone();
        empty["recipients"] = serde_json::json!([]);
        malformed.push(empty);
        let mut null = body.clone();
        null["recipients"] = serde_json::Value::Null;
        malformed.push(null);
        let mut duplicate = body.clone();
        let first = duplicate["recipients"][0].clone();
        duplicate["recipients"].as_array_mut().unwrap().push(first);
        malformed.push(duplicate);
        let mut blank = body.clone();
        blank["recipients"][0]["keyId"] = " ".into();
        malformed.push(blank);
        let mut mismatch = body.clone();
        mismatch["recipients"][0]["recipient"]["keyId"] = "bob".into();
        malformed.push(mismatch);
        let mut unknown_recipient_field = body.clone();
        unknown_recipient_field["recipients"][0]["extra"] = true.into();
        malformed.push(unknown_recipient_field);
        let mut null_recipient = body.clone();
        null_recipient["recipients"][0]["recipient"] = serde_json::Value::Null;
        malformed.push(null_recipient);

        for invalid in malformed {
            let invalid = cvk(
                envelope.header_bytes(),
                &serde_json::to_vec(&invalid).unwrap(),
            );
            let invalid = CvkEnvelope::parse(&invalid).unwrap();
            assert!(
                unlock_with_private_key(&invalid, key).is_err(),
                "{algorithm:?}"
            );
        }
    }
}

#[test]
fn public_protection_rejects_invalid_recipients_and_small_rsa_keys() {
    let rsa = PKey::from_rsa(Rsa::generate(1024).unwrap()).unwrap();
    let recipient = load_public_key(&rsa.public_key_to_pem().unwrap(), "alice").unwrap();
    let mut payload = CvkPayload {
        cek: [42; 32],
        recipient_keys: vec![recipient.clone()],
    };
    let mut header = CvkHeader {
        version: 1,
        key_protection: KeyWrapAlgorithm::RsaOaepSha256.protection(),
        key_wrap_algorithm: KeyWrapAlgorithm::RsaOaepSha256,
        label: None,
        description: None,
        comment: None,
        created_at: None,
        generator: None,
    };
    let bytes = encode(&header, &payload, None).unwrap();
    assert_eq!(
        unlock_with_private_key(&CvkEnvelope::parse(&bytes).unwrap(), &rsa)
            .unwrap()
            .cek,
        [42; 32]
    );
    header.key_wrap_algorithm = KeyWrapAlgorithm::RsaOaepSha512;
    assert!(encode(&header, &payload, None).is_err());
    header.key_wrap_algorithm = KeyWrapAlgorithm::EcdhP256;
    assert!(encode(&header, &payload, None).is_err());
    header.key_wrap_algorithm = KeyWrapAlgorithm::RsaOaepSha256;
    payload.recipient_keys.push(recipient);
    assert!(encode(&header, &payload, None).is_err());
    payload.recipient_keys.clear();
    assert!(encode(&header, &payload, None).is_err());
    header.key_wrap_algorithm = KeyWrapAlgorithm::EcdhP256;
    assert!(encode(&header, &payload, None).is_err());
    let ec = PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
    )
    .unwrap();
    payload
        .recipient_keys
        .push(load_public_key(&ec.public_key_to_pem().unwrap(), "ec").unwrap());
    header.key_wrap_algorithm = KeyWrapAlgorithm::RsaOaepSha256;
    assert!(encode(&header, &payload, None).is_err());
}

#[test]
fn rsa_rejects_unwrapped_keys_with_wrong_length() {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let plain_header = CvkHeader {
        version: 1,
        key_protection: KeyWrapAlgorithm::None.protection(),
        key_wrap_algorithm: KeyWrapAlgorithm::None,
        label: None,
        description: None,
        comment: None,
        created_at: None,
        generator: None,
    };
    let plain_payload = CvkPayload {
        cek: [0; 32],
        recipient_keys: Vec::new(),
    };
    let plain = encode(&plain_header, &plain_payload, None).unwrap();
    assert!(unlock_with_private_key(&CvkEnvelope::parse(&plain).unwrap(), &key).is_err());
    let recipient = load_public_key(&key.public_key_to_pem().unwrap(), "alice").unwrap();
    let payload = CvkPayload {
        cek: [42; 32],
        recipient_keys: vec![recipient],
    };
    let header = CvkHeader {
        version: 1,
        key_protection: KeyWrapAlgorithm::RsaOaepSha256.protection(),
        key_wrap_algorithm: KeyWrapAlgorithm::RsaOaepSha256,
        label: None,
        description: None,
        comment: None,
        created_at: None,
        generator: None,
    };
    let bytes = encode(&header, &payload, None).unwrap();
    let envelope = CvkEnvelope::parse(&bytes).unwrap();
    let mut body: serde_json::Value = serde_json::from_slice(envelope.key_body()).unwrap();
    let public = PKey::public_key_from_der(&key.public_key_to_der().unwrap()).unwrap();
    let mut encrypter = Encrypter::new(&public).unwrap();
    encrypter.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
    encrypter.set_rsa_oaep_md(MessageDigest::sha256()).unwrap();
    encrypter.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
    let mut wrapped = vec![0; encrypter.encrypt_len(&[7; 16]).unwrap()];
    let length = encrypter.encrypt(&[7; 16], &mut wrapped).unwrap();
    wrapped.truncate(length);
    body["recipients"][0]["wrappedKey"] = STANDARD.encode(wrapped).into();
    let bytes = cvk(envelope.header_bytes(), &serde_json::to_vec(&body).unwrap());
    assert!(unlock_with_private_key(&CvkEnvelope::parse(&bytes).unwrap(), &key).is_err());
}
