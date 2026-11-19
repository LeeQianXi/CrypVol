use std::{fs, path::Path, process::Command};

use super::support::{TempDir, command, failure, reference, success};

#[test]
fn certificate_encrypted_pem_and_ssh_discovery() {
    let temp = TempDir::new();
    let directory = temp.0.to_str().unwrap();
    let rust = Path::new(env!("CARGO_BIN_EXE_crypvol-cli"));
    let private = temp.0.join("encrypted.pem");
    let certificate = temp.0.join("certificate.pem");
    let private = private.to_str().unwrap();
    let certificate = certificate.to_str().unwrap();
    success(command(
        Path::new("openssl"),
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-days",
            "1",
            "-subj",
            "/CN=CrypVol test",
            "-keyout",
            private,
            "-out",
            certificate,
            "-passout",
            "pass:example",
        ],
    ));
    success(command(
        rust,
        &[
            "genkey",
            "-o",
            directory,
            "-n",
            "cert",
            "-m",
            "PublicKey",
            "--public-key",
            certificate,
        ],
    ));
    let cvk = temp.0.join("cert.cvk");
    let cvk = cvk.to_str().unwrap();
    success(command(
        rust,
        &[
            "info",
            cvk,
            "--privkey-key",
            private,
            "--key-pass",
            "example",
        ],
    ));
    failure(command(
        rust,
        &["info", cvk, "--privkey-key", private, "--key-pass", "wrong"],
    ));
    failure(command(rust, &["info", cvk, "--privkey-key", private]));

    let ssh_dir = temp.0.join(".ssh");
    fs::create_dir(&ssh_dir).unwrap();
    let ssh_private = ssh_dir.join("id_rsa");
    let ssh_public = ssh_dir.join("id_rsa.pub");
    let ssh_private = ssh_private.to_str().unwrap();
    let ssh_public = ssh_public.to_str().unwrap();
    success(command(
        Path::new("ssh-keygen"),
        &[
            "-q",
            "-t",
            "rsa",
            "-b",
            "2048",
            "-N",
            "",
            "-C",
            "",
            "-f",
            ssh_private,
        ],
    ));
    success(command(
        rust,
        &[
            "genkey",
            "-o",
            directory,
            "-n",
            "ssh-auto",
            "-m",
            "PublicKey",
            "--public-key",
            ssh_public,
        ],
    ));
    let cvk = temp.0.join("ssh-auto.cvk");
    let output = Command::new(rust)
        .args(["info", cvk.to_str().unwrap()])
        .env("HOME", directory)
        .output()
        .unwrap();
    let info = success(output);
    assert!(info.contains("id_rsa (RSA)"));
    let output = Command::new(rust)
        .args(["info", cvk.to_str().unwrap()])
        .env_remove("HOME")
        .env("USERPROFILE", directory)
        .output()
        .unwrap();
    success(output);
    let unrelated = temp.0.join("cert.cvk");
    let output = Command::new(rust)
        .args(["info", unrelated.to_str().unwrap()])
        .env("HOME", directory)
        .output()
        .unwrap();
    failure(output);
}

#[test]
fn openssh_encrypted_private_key_and_validation() {
    let temp = TempDir::new();
    let directory = temp.0.to_str().unwrap();
    let rust = Path::new(env!("CARGO_BIN_EXE_crypvol-cli"));
    let private = temp.0.join("ssh-rsa");
    let public = temp.0.join("ssh-rsa.pub");
    let private = private.to_str().unwrap();
    let public = public.to_str().unwrap();
    success(command(
        Path::new("ssh-keygen"),
        &[
            "-q",
            "-t",
            "rsa",
            "-b",
            "2048",
            "-N",
            "example",
            "-C",
            "PRIVATE KEY recipient",
            "-f",
            private,
        ],
    ));
    let output_dir = temp.0.join("nested");
    let output_dir = output_dir.to_str().unwrap();
    success(command(
        rust,
        &[
            "genkey",
            "-o",
            output_dir,
            "-n",
            "archive",
            "-m",
            "PublicKey",
            "--public-key",
            public,
        ],
    ));
    let cvk = temp.0.join("nested/archive.cvk");
    let path = cvk.to_str().unwrap();
    let before = fs::read(&cvk).unwrap();
    let info = success(command(
        rust,
        &[
            "info",
            path,
            "--privkey-key",
            private,
            "--key-pass",
            "example",
        ],
    ));
    assert!(info.contains("PRIVATE KEY recipient"));
    failure(command(
        rust,
        &[
            "info",
            path,
            "--privkey-key",
            private,
            "--key-pass",
            "wrong",
        ],
    ));
    failure(command(
        rust,
        &[
            "rekey",
            path,
            "--privkey-key",
            private,
            "--key-pass",
            "example",
            "--remove-public-key",
            "missing",
            "--backup=false",
        ],
    ));
    assert_eq!(fs::read(&cvk).unwrap(), before);
    let damaged = temp.0.join("damaged-private");
    let mut contents = fs::read(private).unwrap();
    let marker = contents.iter().position(|&byte| byte == b'\n').unwrap() + 2;
    contents[marker] = b'!';
    fs::write(&damaged, contents).unwrap();
    failure(command(
        rust,
        &[
            "info",
            path,
            "--privkey-key",
            damaged.to_str().unwrap(),
            "--key-pass",
            "example",
        ],
    ));
    assert_eq!(fs::read(&cvk).unwrap(), before);
    failure(command(
        rust,
        &[
            "genkey",
            "-o",
            directory,
            "-n",
            "invalid",
            "--public-key",
            public,
        ],
    ));
    assert!(!temp.0.join("invalid.cvk").exists());
    if let Some(reference) = reference() {
        success(command(
            &reference,
            &[
                "info",
                path,
                "--privkey-key",
                private,
                "--key-pass",
                "example",
            ],
        ));
    }
    let bom = b"\xef\xbb\xbf";
    let public_with_bom = [bom.as_slice(), &fs::read(public).unwrap()].concat();
    fs::write(public, public_with_bom).unwrap();
    success(command(
        rust,
        &[
            "genkey",
            "-o",
            directory,
            "-n",
            "bom",
            "-m",
            "PublicKey",
            "--public-key",
            public,
        ],
    ));
    let private_with_bom = [bom.as_slice(), &fs::read(private).unwrap()].concat();
    fs::write(private, private_with_bom).unwrap();
    let bom_cvk = temp.0.join("bom.cvk");
    success(command(
        rust,
        &[
            "info",
            bom_cvk.to_str().unwrap(),
            "--privkey-key",
            private,
            "--key-pass",
            "example",
        ],
    ));
}
