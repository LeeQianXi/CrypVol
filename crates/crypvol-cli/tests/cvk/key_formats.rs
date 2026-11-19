use std::path::Path;

use super::support::{TempDir, command, failure, reference, success};

#[test]
fn rsa_pkcs1_pem_and_encrypted_private_key_interoperate() {
    let temp = TempDir::new();
    let directory = temp.0.to_str().unwrap();
    let rust = Path::new(env!("CARGO_BIN_EXE_crypvol-cli"));
    let private = temp.0.join("rsa-private.pem");
    let encrypted = temp.0.join("rsa-encrypted.pem");
    let public = temp.0.join("rsa-public.pem");
    let private = private.to_str().unwrap();
    let encrypted = encrypted.to_str().unwrap();
    let public = public.to_str().unwrap();

    success(command(
        Path::new("openssl"),
        &["genrsa", "-traditional", "-out", private, "2048"],
    ));
    success(command(
        Path::new("openssl"),
        &["rsa", "-in", private, "-RSAPublicKey_out", "-out", public],
    ));
    success(command(
        Path::new("openssl"),
        &[
            "rsa",
            "-in",
            private,
            "-traditional",
            "-aes256",
            "-passout",
            "pass:example",
            "-out",
            encrypted,
        ],
    ));
    success(command(
        rust,
        &[
            "genkey",
            "-o",
            directory,
            "-n",
            "rsa",
            "-m",
            "PublicKey",
            "--public-key",
            public,
            "--cek",
            &"ab".repeat(32),
        ],
    ));
    let cvk = temp.0.join("rsa.cvk");
    let path = cvk.to_str().unwrap();
    for (private, password) in [(private, None), (encrypted, Some("example"))] {
        let mut args = vec!["info", path, "--privkey-key", private];
        if let Some(password) = password {
            args.extend(["--key-pass", password]);
        }
        let output = success(command(rust, &args));
        assert!(output.contains("9A2DB2E23F1504CD"));
        if let Some(reference) = reference() {
            let output = command(&reference, &args);
            if password.is_none() {
                assert!(success(output).contains("9A2DB2E23F1504CD"));
            } else {
                assert!(output.status.success());
                assert!(String::from_utf8_lossy(&output.stdout).contains("未解封"));
            }
        }
    }
    failure(command(
        rust,
        &[
            "info",
            path,
            "--privkey-key",
            encrypted,
            "--key-pass",
            "incorrect",
        ],
    ));
    failure(command(rust, &["info", path, "--privkey-key", encrypted]));
}

#[test]
fn unsupported_openssh_keys_are_rejected() {
    let temp = TempDir::new();
    let private = temp.0.join("ed25519");
    let private = private.to_str().unwrap();
    success(command(
        Path::new("ssh-keygen"),
        &["-q", "-t", "ed25519", "-N", "", "-f", private],
    ));
    let public = format!("{private}.pub");
    let rust = Path::new(env!("CARGO_BIN_EXE_crypvol-cli"));
    failure(command(
        rust,
        &[
            "genkey",
            "-o",
            temp.0.to_str().unwrap(),
            "-n",
            "unsupported",
            "-m",
            "PublicKey",
            "--public-key",
            &public,
        ],
    ));
    let rsa_private = temp.0.join("rsa.pem");
    let rsa_private = rsa_private.to_str().unwrap();
    let rsa_public = temp.0.join("rsa.pub");
    let rsa_public = rsa_public.to_str().unwrap();
    success(command(
        Path::new("openssl"),
        &["genrsa", "-out", rsa_private, "2048"],
    ));
    success(command(
        Path::new("openssl"),
        &["rsa", "-in", rsa_private, "-pubout", "-out", rsa_public],
    ));
    success(command(
        rust,
        &[
            "genkey",
            "-o",
            temp.0.to_str().unwrap(),
            "-n",
            "rsa",
            "-m",
            "PublicKey",
            "--public-key",
            rsa_public,
        ],
    ));
    failure(command(
        rust,
        &[
            "info",
            temp.0.join("rsa.cvk").to_str().unwrap(),
            "--privkey-key",
            private,
        ],
    ));
}
