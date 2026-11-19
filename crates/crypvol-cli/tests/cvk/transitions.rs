use std::{fs, path::Path};

use super::support::{TempDir, command, failure, make_key, success};

#[test]
fn protection_changes_and_recipient_replacement_preserve_source() {
    let temp = TempDir::new();
    let directory = temp.0.to_str().unwrap();
    let rust = Path::new(env!("CARGO_BIN_EXE_crypvol-cli"));
    let (alice_private, alice_public) = make_key(&temp.0, "alice", None);
    let (bob_private, bob_public) = make_key(&temp.0, "bob", None);
    let source = temp.0.join("original.cvk");
    let source_path = source.to_str().unwrap();
    success(command(
        rust,
        &[
            "genkey",
            "-o",
            directory,
            "-n",
            "original",
            "--cek",
            &"ab".repeat(32),
        ],
    ));
    let original = fs::read(&source).unwrap();
    let password_cvk = temp.0.join("nested/password.cvk");
    let password_path = password_cvk.to_str().unwrap();
    success(command(
        rust,
        &[
            "rekey",
            source_path,
            "--to-mode",
            "Password",
            "--new-password",
            "example",
            "--output",
            password_path,
            "--backup=false",
        ],
    ));
    assert_eq!(fs::read(&source).unwrap(), original);
    assert!(
        success(command(rust, &["info", password_path, "-p", "example"]))
            .contains("9A2DB2E23F1504CD")
    );
    let public_cvk = temp.0.join("public.cvk");
    let public_path = public_cvk.to_str().unwrap();
    success(command(
        rust,
        &[
            "rekey",
            password_path,
            "-p",
            "example",
            "--to-mode",
            "PublicKey",
            "--public-key",
            alice_public.to_str().unwrap(),
            "--output",
            public_path,
            "--backup=false",
        ],
    ));
    success(command(
        rust,
        &[
            "rekey",
            public_path,
            "--privkey-key",
            alice_private.to_str().unwrap(),
            "--clear-public-keys",
            "--public-key",
            bob_public.to_str().unwrap(),
            "--backup=false",
        ],
    ));
    failure(command(
        rust,
        &[
            "info",
            public_path,
            "--privkey-key",
            alice_private.to_str().unwrap(),
        ],
    ));
    assert!(
        success(command(
            rust,
            &[
                "info",
                public_path,
                "--privkey-key",
                bob_private.to_str().unwrap()
            ]
        ))
        .contains("9A2DB2E23F1504CD")
    );
    let unchanged = fs::read(&public_cvk).unwrap();
    failure(command(
        rust,
        &[
            "rekey",
            public_path,
            "--privkey-key",
            bob_private.to_str().unwrap(),
            "--remove-public-key",
            "bob",
            "--backup=false",
        ],
    ));
    failure(command(
        rust,
        &[
            "rekey",
            public_path,
            "--privkey-key",
            bob_private.to_str().unwrap(),
            "--public-key",
            bob_public.to_str().unwrap(),
            "--backup=false",
        ],
    ));
    assert_eq!(fs::read(&public_cvk).unwrap(), unchanged);
}
