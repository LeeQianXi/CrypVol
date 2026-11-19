use std::{fs, path::Path};

use super::support::{TempDir, command, failure, make_key, success};

#[test]
fn invalid_routes_and_credentials_leave_existing_files_unchanged() {
    let temp = TempDir::new();
    let directory = temp.0.to_str().unwrap();
    let rust = Path::new(env!("CARGO_BIN_EXE_crypvol-cli"));
    let (private, public) = make_key(&temp.0, "alice", None);
    let private = private.to_str().unwrap();
    let public = public.to_str().unwrap();
    for args in [
        vec!["genkey", "-o", directory, "-n", "invalid", "-m", "Password"],
        vec![
            "genkey", "-o", directory, "-n", "invalid", "-m", "Password", "-p", "   ",
        ],
        vec![
            "genkey",
            "-o",
            directory,
            "-n",
            "invalid",
            "-m",
            "PublicKey",
        ],
        vec![
            "genkey",
            "-o",
            directory,
            "-n",
            "invalid",
            "-m",
            "PublicKey",
            "--public-key",
            public,
            "-p",
            "unexpected",
        ],
        vec![
            "genkey",
            "-o",
            directory,
            "-n",
            "invalid",
            "-m",
            "Plain",
            "--algorithm",
            "PasswordArgon2Id",
        ],
        vec!["genkey", "-o", directory, "-n", "invalid", "--cek", "123"],
    ] {
        failure(command(rust, &args));
        assert!(!temp.0.join("invalid.cvk").exists());
    }
    success(command(
        rust,
        &[
            "genkey",
            "-o",
            directory,
            "-n",
            "protected",
            "-m",
            "Password",
            "-p",
            "example",
            "--cek",
            &"ab".repeat(32),
        ],
    ));
    let cvk = temp.0.join("protected.cvk");
    let path = cvk.to_str().unwrap();
    let original = fs::read(&cvk).unwrap();
    failure(command(
        rust,
        &[
            "genkey",
            "-o",
            directory,
            "-n",
            "protected",
            "--cek",
            &"cd".repeat(32),
        ],
    ));
    assert_eq!(fs::read(&cvk).unwrap(), original);
    let backup = temp.0.join("protected.cvk.bak");
    failure(command(
        rust,
        &[
            "rekey",
            path,
            "-p",
            "example",
            "--to-mode",
            "Plain",
            "--output",
            backup.to_str().unwrap(),
        ],
    ));
    assert!(!backup.exists());
    assert_eq!(fs::read(&cvk).unwrap(), original);
    for args in [
        vec![
            "rekey",
            path,
            "-p",
            "wrong",
            "--to-mode",
            "Plain",
            "--backup=false",
        ],
        vec![
            "rekey",
            path,
            "-p",
            "example",
            "--to-mode",
            "PublicKey",
            "--backup=false",
        ],
        vec![
            "rekey",
            path,
            "-p",
            "example",
            "--to-mode",
            "Plain",
            "--new-password",
            "invalid",
            "--backup=false",
        ],
        vec![
            "rekey",
            path,
            "-p",
            "example",
            "--to-mode",
            "Plain",
            "--public-key",
            public,
            "--backup=false",
        ],
        vec![
            "rekey",
            path,
            "--privkey-key",
            private,
            "--to-mode",
            "Plain",
            "--backup=false",
        ],
    ] {
        failure(command(rust, &args));
        assert_eq!(fs::read(&cvk).unwrap(), original);
    }
}

#[test]
fn invalid_names_and_unneeded_credentials_are_rejected() {
    let temp = TempDir::new();
    let directory = temp.0.to_str().unwrap();
    let rust = Path::new(env!("CARGO_BIN_EXE_crypvol-cli"));
    for name in [" ", ".", "..", "already.cvk", "../escape"] {
        failure(command(rust, &["genkey", "-o", directory, "-n", name]));
    }
    success(command(
        rust,
        &[
            "genkey",
            "-o",
            directory,
            "-n",
            "plain",
            "--algorithm",
            "None",
        ],
    ));
    let cvk = temp.0.join("plain.cvk");
    let cvk = cvk.to_str().unwrap();
    failure(command(rust, &["info", cvk, "--password", "unneeded"]));
    failure(command(
        rust,
        &["rekey", cvk, "--to-mode", "Password", "--backup=false"],
    ));
    failure(command(
        rust,
        &[
            "genkey",
            "-o",
            directory,
            "-n",
            "password",
            "-m",
            "Password",
            "--algorithm",
            "None",
            "-p",
            "example",
        ],
    ));
    success(command(
        rust,
        &[
            "genkey", "-o", directory, "-n", "password", "-m", "Password", "-p", "example",
        ],
    ));
    let cvk = temp.0.join("password.cvk");
    let info = success(command(
        rust,
        &["info", cvk.to_str().unwrap(), "-p", "example"],
    ));
    assert!(info.contains("PasswordPbkdf2Sha256"));
}

#[test]
fn rekey_rejects_irrelevant_credentials_and_can_clear_metadata() {
    let temp = TempDir::new();
    let directory = temp.0.to_str().unwrap();
    let rust = Path::new(env!("CARGO_BIN_EXE_crypvol-cli"));
    success(command(
        rust,
        &[
            "genkey",
            "-o",
            directory,
            "-n",
            "plain",
            "--comment",
            "original",
        ],
    ));
    let plain = temp.0.join("plain.cvk");
    let plain = plain.to_str().unwrap();
    failure(command(
        rust,
        &["rekey", plain, "--password", "unneeded", "--backup=false"],
    ));
    success(command(
        rust,
        &[
            "rekey",
            plain,
            "--label",
            "label",
            "--description",
            "description",
            "--backup=false",
        ],
    ));
    success(command(
        rust,
        &[
            "rekey",
            plain,
            "--clear-label",
            "--clear-description",
            "--clear-comment",
            "--backup=false",
        ],
    ));
    let info = success(command(rust, &["info", plain]));
    assert!(!info.contains("标签："));
    assert!(!info.contains("描述："));
    assert!(!info.contains("注释："));

    let (_, public) = make_key(&temp.0, "recipient", None);
    success(command(
        rust,
        &[
            "genkey",
            "-o",
            directory,
            "-n",
            "public",
            "-m",
            "PublicKey",
            "--public-key",
            public.to_str().unwrap(),
        ],
    ));
    let public = temp.0.join("public.cvk");
    let public = public.to_str().unwrap();
    failure(command(rust, &["info", public, "--password", "unneeded"]));
    failure(command(
        rust,
        &["rekey", public, "--password", "unneeded", "--backup=false"],
    ));
}

#[test]
fn oversized_cvk_is_rejected_without_modification() {
    let temp = TempDir::new();
    let rust = Path::new(env!("CARGO_BIN_EXE_crypvol-cli"));
    let cvk = temp.0.join("oversized.cvk");
    let file = fs::File::create(&cvk).unwrap();
    let length = 16 + 1024 * 1024 + 256 * 1024 * 1024 + 33;
    file.set_len(length).unwrap();
    drop(file);
    let path = cvk.to_str().unwrap();
    failure(command(rust, &["info", path]));
    failure(command(rust, &["rekey", path, "--backup=false"]));
    assert_eq!(fs::metadata(&cvk).unwrap().len(), length);
}
