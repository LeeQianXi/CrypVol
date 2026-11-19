use crypvol_core::crypto::{
    CvkEnvelope, CvkHeader, CvkPayload, KeyWrapAlgorithm, encode, load_public_key, unlock,
    unlock_with_private_key,
};
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
};

fn header(algorithm: KeyWrapAlgorithm) -> CvkHeader {
    CvkHeader {
        version: 1,
        key_protection: algorithm.protection(),
        key_wrap_algorithm: algorithm,
        label: None,
        description: None,
        comment: Some("测试 metadata".into()),
        created_at: None,
        generator: None,
    }
}

fn assert_hidden(body: &[u8], cek: &[u8; 32]) {
    assert!(!body.windows(cek.len()).any(|window| window == cek));
}

#[test]
fn password_routes_use_fresh_parameters_and_unicode_passwords() {
    for algorithm in [
        KeyWrapAlgorithm::PasswordPbkdf2Sha256,
        KeyWrapAlgorithm::PasswordArgon2Id,
    ] {
        let payload = CvkPayload {
            cek: [0xa5; 32],
            recipient_keys: Vec::new(),
        };
        let password = "密码 🔐";
        let first = encode(&header(algorithm), &payload, Some(password)).unwrap();
        let second = encode(&header(algorithm), &payload, Some(password)).unwrap();
        let first = CvkEnvelope::parse(&first).unwrap();
        let second = CvkEnvelope::parse(&second).unwrap();
        assert_ne!(first.key_body(), second.key_body());
        assert_hidden(first.key_body(), &payload.cek);
        assert_eq!(unlock(&first, Some(password)).unwrap().cek, payload.cek);
        assert_eq!(unlock(&second, Some(password)).unwrap().cek, payload.cek);
    }
}

#[test]
fn public_routes_use_fresh_parameters_and_do_not_expose_cek() {
    let rsa = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let ec_key = |curve| -> PKey<Private> {
        let group = EcGroup::from_curve_name(curve).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    };
    let p256 = ec_key(Nid::X9_62_PRIME256V1);
    let p384 = ec_key(Nid::SECP384R1);
    let p521 = ec_key(Nid::SECP521R1);
    for (algorithm, key) in [
        (KeyWrapAlgorithm::RsaOaepSha256, &rsa),
        (KeyWrapAlgorithm::RsaOaepSha384, &rsa),
        (KeyWrapAlgorithm::RsaOaepSha512, &rsa),
        (KeyWrapAlgorithm::EcdhP256, &p256),
        (KeyWrapAlgorithm::EcdhP384, &p384),
        (KeyWrapAlgorithm::EcdhP521, &p521),
    ] {
        let recipient = load_public_key(&key.public_key_to_pem().unwrap(), "recipient").unwrap();
        let payload = CvkPayload {
            cek: [0xa5; 32],
            recipient_keys: vec![recipient],
        };
        let first = encode(&header(algorithm), &payload, None).unwrap();
        let second = encode(&header(algorithm), &payload, None).unwrap();
        let first = CvkEnvelope::parse(&first).unwrap();
        let second = CvkEnvelope::parse(&second).unwrap();
        assert_ne!(first.key_body(), second.key_body());
        assert_hidden(first.key_body(), &payload.cek);
        assert_eq!(
            unlock_with_private_key(&first, key).unwrap().cek,
            payload.cek
        );
        assert_eq!(
            unlock_with_private_key(&second, key).unwrap().cek,
            payload.cek
        );
    }
}
