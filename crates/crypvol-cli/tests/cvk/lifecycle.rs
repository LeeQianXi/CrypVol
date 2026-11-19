use std::{fs, path::Path};

use super::support::{TempDir, command, failure, make_key, reference, success};

#[test]
fn plain_documents_round_trip_with_reference() {
    let temp = TempDir::new();
    let directory = temp.0.to_str().unwrap();
    let rust = Path::new(env!("CARGO_BIN_EXE_crypvol-cli"));
    let Some(reference) = reference() else {
        return;
    };
    for (producer, consumer, name) in [
        (rust, reference.as_path(), "rust-plain"),
        (reference.as_path(), rust, "net-plain"),
    ] {
        success(command(
            producer,
            &[
                "genkey",
                "-o",
                directory,
                "-n",
                name,
                "--cek",
                &"ab".repeat(32),
                "--comment",
                "中文 \"+😀",
            ],
        ));
        let cvk = temp.0.join(format!("{name}.cvk"));
        let path = cvk.to_str().unwrap();
        let info = success(command(consumer, &["info", path]));
        assert!(info.contains("9A2DB2E23F1504CD"));
        success(command(consumer, &["rekey", path, "--label", "new"]));
        let info = success(command(producer, &["info", path]));
        assert!(info.contains("9A2DB2E23F1504CD"));
    }
}

#[test]
fn nonzero_header_version_survives_rekey_and_reference() {
    use crypvol_core::crypto::{
        CvkEnvelope, CvkHeader, CvkPayload, KeyProtection, KeyWrapAlgorithm, encode,
    };

    let temp = TempDir::new();
    let rust = Path::new(env!("CARGO_BIN_EXE_crypvol-cli"));
    for version in [2, u16::MAX] {
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
        let cvk = temp.0.join(format!("version-{version}.cvk"));
        fs::write(&cvk, encode(&header, &payload, None).unwrap()).unwrap();
        let path = cvk.to_str().unwrap();
        if let Some(reference) = reference() {
            let output = success(command(&reference, &["info", path]));
            assert!(output.contains(&format!("版本: {version}")));
        }
        success(command(
            rust,
            &["rekey", path, "--label", "kept", "--backup=false"],
        ));
        let bytes = fs::read(&cvk).unwrap();
        assert_eq!(
            CvkEnvelope::parse(&bytes).unwrap().header().version,
            version
        );
        if let Some(reference) = reference() {
            let output = success(command(&reference, &["info", path]));
            assert!(output.contains(&format!("版本: {version}")));
        }
    }
}

#[test]
fn recipients_and_password_rotation_preserve_key_and_backup() {
    let temp = TempDir::new();
    let directory = temp.0.to_str().unwrap();
    let rust = Path::new(env!("CARGO_BIN_EXE_crypvol-cli"));
    let (alice_private, alice_public) = make_key(&temp.0, "alice", None);
    let (bob_private, bob_public) = make_key(&temp.0, "bob", None);
    let alice_private = alice_private.to_str().unwrap();
    let alice_public = alice_public.to_str().unwrap();
    let bob_private = bob_private.to_str().unwrap();
    let bob_public = bob_public.to_str().unwrap();
    let cvk = temp.0.join("archive.cvk");
    let path = cvk.to_str().unwrap();
    success(command(
        rust,
        &[
            "genkey",
            "-o",
            directory,
            "-n",
            "archive",
            "-m",
            "PublicKey",
            "--public-key",
            alice_public,
            "--public-key",
            bob_public,
            "--cek",
            &"ab".repeat(32),
        ],
    ));
    let original = fs::read(&cvk).unwrap();
    let before = success(command(rust, &["info", path, "--privkey-key", bob_private]));
    assert!(before.contains("9A2DB2E23F1504CD"));
    success(command(
        rust,
        &[
            "rekey",
            path,
            "--privkey-key",
            alice_private,
            "--remove-public-key",
            "bob",
        ],
    ));
    assert_eq!(fs::read(temp.0.join("archive.cvk.bak")).unwrap(), original);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&cvk, &temp.0.join("archive.cvk.bak")] {
            assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o077, 0);
        }
    }
    failure(command(rust, &["info", path, "--privkey-key", bob_private]));
    assert!(
        success(command(
            rust,
            &["info", path, "--privkey-key", alice_private]
        ))
        .contains("9A2DB2E23F1504CD")
    );
    let current = fs::read(&cvk).unwrap();
    failure(command(
        rust,
        &[
            "rekey",
            path,
            "--privkey-key",
            alice_private,
            "--public-key",
            bob_public,
        ],
    ));
    assert_eq!(fs::read(&cvk).unwrap(), current);
    success(command(
        rust,
        &[
            "rekey",
            path,
            "--privkey-key",
            alice_private,
            "--to-mode",
            "Password",
            "--new-password",
            "example",
            "--backup=false",
        ],
    ));
    failure(command(rust, &["info", path, "--password", "wrong"]));
    assert!(
        success(command(rust, &["info", path, "--password", "example"]))
            .contains("9A2DB2E23F1504CD")
    );
    if let Some(reference) = reference() {
        success(command(
            &reference,
            &["info", path, "--password", "example"],
        ));
    }
}

#[test]
fn ecdh_multiple_recipients_can_rotate_independently() {
    let temp = TempDir::new();
    let directory = temp.0.to_str().unwrap();
    let rust = Path::new(env!("CARGO_BIN_EXE_crypvol-cli"));
    for (algorithm, curve) in [
        ("EcdhP256", "ec_paramgen_curve:prime256v1"),
        ("EcdhP384", "ec_paramgen_curve:secp384r1"),
        ("EcdhP521", "ec_paramgen_curve:secp521r1"),
    ] {
        let alice_id = format!("{algorithm}-alice");
        let bob_id = format!("{algorithm}-bob");
        let (alice_private, alice_public) = make_key(&temp.0, &alice_id, Some(curve));
        let (bob_private, bob_public) = make_key(&temp.0, &bob_id, Some(curve));
        let archive = temp.0.join(format!("{algorithm}.cvk"));
        let path = archive.to_str().unwrap();
        let alice_private = alice_private.to_str().unwrap();
        let bob_private = bob_private.to_str().unwrap();
        success(command(
            rust,
            &[
                "genkey",
                "-o",
                directory,
                "-n",
                algorithm,
                "-m",
                "PublicKey",
                "--algorithm",
                algorithm,
                "--public-key",
                alice_public.to_str().unwrap(),
                "--public-key",
                bob_public.to_str().unwrap(),
                "--cek",
                &"ab".repeat(32),
            ],
        ));
        for private in [alice_private, bob_private] {
            assert!(
                success(command(rust, &["info", path, "--privkey-key", private]))
                    .contains("9A2DB2E23F1504CD")
            );
            if let Some(reference) = reference() {
                assert!(
                    success(command(
                        &reference,
                        &["info", path, "--privkey-key", private]
                    ))
                    .contains("9A2DB2E23F1504CD")
                );
            }
        }
        success(command(
            rust,
            &[
                "rekey",
                path,
                "--privkey-key",
                bob_private,
                "--remove-public-key",
                &alice_id,
                "--backup=false",
            ],
        ));
        failure(command(
            rust,
            &["info", path, "--privkey-key", alice_private],
        ));
        assert!(
            success(command(rust, &["info", path, "--privkey-key", bob_private]))
                .contains("9A2DB2E23F1504CD")
        );
    }
}
