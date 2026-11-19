use super::{algorithm, protection};
use crypvol_core::crypto::{KeyProtection, KeyWrapAlgorithm};

#[test]
fn protection_names_and_default_algorithms_are_validated() {
    assert_eq!(protection("Plain").unwrap(), KeyProtection::Plain);
    assert_eq!(protection("pAsSwOrD").unwrap(), KeyProtection::Password);
    assert_eq!(protection("PUBLICKEY").unwrap(), KeyProtection::PublicKey);
    assert!(protection("unknown").is_err());

    for (mode, expected) in [
        (KeyProtection::Plain, KeyWrapAlgorithm::None),
        (
            KeyProtection::Password,
            KeyWrapAlgorithm::PasswordPbkdf2Sha256,
        ),
        (KeyProtection::PublicKey, KeyWrapAlgorithm::RsaOaepSha256),
    ] {
        assert_eq!(algorithm(mode, None).unwrap(), expected);
    }
    assert_eq!(
        algorithm(KeyProtection::Plain, Some(&"None".into())).unwrap(),
        KeyWrapAlgorithm::None
    );
    assert!(algorithm(KeyProtection::Password, Some(&"None".into())).is_err());
    assert!(algorithm(KeyProtection::PublicKey, Some(&"None".into())).is_err());
    assert!(algorithm(KeyProtection::Password, Some(&"RsaOaepSha256".into())).is_err());
    assert!(algorithm(KeyProtection::Plain, Some(&"unknown".into())).is_err());
}
