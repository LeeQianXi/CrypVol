use std::path::Path;

use super::support::{TempDir, command, failure, make_key, reference, success};

#[test]
fn migrate_imports_legacy_password_cvk_before_normal_operations() {
    let Some(reference) = reference() else {
        return;
    };
    let temp = TempDir::new();
    let directory = temp.0.to_str().unwrap();
    let rust = Path::new(env!("CARGO_BIN_EXE_crypvol-cli"));
    success(command(
        &reference,
        &[
            "genkey",
            "-o",
            directory,
            "-n",
            "legacy-password",
            "-m",
            "Password",
            "-p",
            "example",
            "--cek",
            &"ab".repeat(32),
            "--comment",
            "中文 \"+😀",
        ],
    ));
    let legacy = temp.0.join("legacy-password.cvk");
    let native = temp.0.join("native-password.cvk");
    success(command(
        rust,
        &[
            "migrate",
            legacy.to_str().unwrap(),
            "-o",
            native.to_str().unwrap(),
            "-p",
            "example",
        ],
    ));
    let info = success(command(
        rust,
        &["info", native.to_str().unwrap(), "-p", "example"],
    ));
    assert!(info.contains("9A2DB2E23F1504CD"));
}

#[test]
fn migrate_imports_legacy_public_key_cvk() {
    let Some(reference) = reference() else {
        return;
    };
    let temp = TempDir::new();
    let rust = Path::new(env!("CARGO_BIN_EXE_crypvol-cli"));
    let (private, public) = make_key(&temp.0, "recipient", None);
    let legacy = temp.0.join("legacy-public.cvk");
    let native = temp.0.join("native-public.cvk");
    success(command(
        &reference,
        &[
            "genkey",
            "-o",
            temp.0.to_str().unwrap(),
            "-n",
            "legacy-public",
            "-m",
            "PublicKey",
            "--public-key",
            public.to_str().unwrap(),
            "--cek",
            &"ab".repeat(32),
        ],
    ));
    success(command(
        rust,
        &[
            "migrate",
            legacy.to_str().unwrap(),
            "-o",
            native.to_str().unwrap(),
            "--privkey-key",
            private.to_str().unwrap(),
        ],
    ));
    let info = success(command(
        rust,
        &[
            "info",
            native.to_str().unwrap(),
            "--privkey-key",
            private.to_str().unwrap(),
        ],
    ));
    assert!(info.contains("9A2DB2E23F1504CD"));
}

#[test]
fn migrate_rejects_credentials_irrelevant_to_legacy_protection() {
    let Some(reference) = reference() else {
        return;
    };
    let temp = TempDir::new();
    let rust = Path::new(env!("CARGO_BIN_EXE_crypvol-cli"));
    success(command(
        &reference,
        &[
            "genkey",
            "-o",
            temp.0.to_str().unwrap(),
            "-n",
            "legacy-plain",
            "--cek",
            &"ab".repeat(32),
        ],
    ));
    let legacy = temp.0.join("legacy-plain.cvk");
    let output = temp.0.join("native-plain.cvk");
    failure(command(
        rust,
        &[
            "migrate",
            legacy.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "-p",
            "unneeded",
        ],
    ));
    assert!(!output.exists());
}
