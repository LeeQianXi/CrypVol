use crypvol_core::crypto::{RecipientAlgorithm, load_private_key, load_public_key};
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::PKey,
    rsa::Rsa,
    symm::Cipher,
};

#[test]
fn rsa_pem_formats_bom_and_password_validation() {
    let rsa = Rsa::generate(2048).unwrap();
    let key = PKey::from_rsa(rsa).unwrap();
    let public = key.public_key_to_pem().unwrap();
    let public_pkcs1 = key.rsa().unwrap().public_key_to_pem_pkcs1().unwrap();
    let private = key.private_key_to_pem_pkcs8().unwrap();
    let encrypted = key
        .private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), b"example")
        .unwrap();
    let expected = key.public_key_to_der().unwrap();
    let bom = b"\xef\xbb\xbf";

    for public_key in [public.as_slice(), public_pkcs1.as_slice()] {
        let recipient = load_public_key(public_key, "alice").unwrap();
        assert_eq!(recipient.key_id, "alice");
        assert_eq!(recipient.algorithm, RecipientAlgorithm::Rsa);
        assert_eq!(recipient.public_key, expected);
        let with_bom = [bom.as_slice(), public_key].concat();
        assert_eq!(
            load_public_key(&with_bom, "alice").unwrap().public_key,
            expected
        );
    }
    for private_key in [
        private.as_slice(),
        [bom.as_slice(), &private].concat().as_slice(),
    ] {
        assert_eq!(
            load_private_key(private_key, None)
                .unwrap()
                .public_key_to_der()
                .unwrap(),
            expected
        );
        assert!(load_private_key(private_key, Some("unexpected")).is_err());
    }
    let encrypted_with_bom = [bom.as_slice(), &encrypted].concat();
    assert!(load_private_key(&encrypted, Some(&"x".repeat(4096))).is_err());
    for private_key in [&encrypted[..], &encrypted_with_bom] {
        assert_eq!(
            load_private_key(private_key, Some("example"))
                .unwrap()
                .public_key_to_der()
                .unwrap(),
            expected
        );
        assert!(load_private_key(private_key, None).is_err());
        assert!(load_private_key(private_key, Some("wrong")).is_err());
    }
    assert!(load_public_key(&private, "alice").is_err());
    assert!(load_public_key(&[public.as_slice(), private.as_slice()].concat(), "alice").is_err());
    assert!(load_public_key(&[private.as_slice(), public.as_slice()].concat(), "alice").is_err());
    assert!(load_private_key(&public, None).is_err());
    assert!(load_public_key(&public, "  ").is_err());
}

#[test]
fn ec_pem_curves_and_unsupported_keys() {
    for curve in [Nid::X9_62_PRIME256V1, Nid::SECP384R1, Nid::SECP521R1] {
        let group = EcGroup::from_curve_name(curve).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let recipient = load_public_key(&key.public_key_to_pem().unwrap(), "recipient").unwrap();
        assert_eq!(recipient.algorithm, RecipientAlgorithm::Ecdh);
        assert_eq!(recipient.public_key, key.public_key_to_der().unwrap());
        let private = key.private_key_to_pem_pkcs8().unwrap();
        assert_eq!(
            load_private_key(&private, None)
                .unwrap()
                .public_key_to_der()
                .unwrap(),
            recipient.public_key
        );
    }
    let unsupported = PKey::generate_ed25519().unwrap();
    assert!(load_public_key(&unsupported.public_key_to_pem().unwrap(), "unsupported").is_err());
    for invalid in [b"".as_slice(), b"   ", b"not a key", &[0xff, 0xfe]] {
        assert!(load_public_key(invalid, "key").is_err());
        assert!(load_private_key(invalid, None).is_err());
    }
}
