use std::{fs, path::Path};

use super::support::{TempDir, command, failure, reference, success};

#[test]
fn password_modes_reference_and_tampering() {
    let temp = TempDir::new();
    let directory = temp.0.to_str().unwrap();
    let rust = Path::new(env!("CARGO_BIN_EXE_crypvol-cli"));
    let reference = reference();
    for algorithm in ["PasswordPbkdf2Sha256", "PasswordArgon2Id"] {
        let name = format!("rust-{algorithm}");
        let cvk = temp.0.join(format!("{name}.cvk"));
        let path = cvk.to_str().unwrap();
        success(command(
            rust,
            &[
                "genkey",
                "-o",
                directory,
                "-n",
                &name,
                "-m",
                "Password",
                "--algorithm",
                algorithm,
                "-p",
                "example",
                "--cek",
                &"ab".repeat(32),
                "--comment",
                "中文 \"+😀\u{000b}\u{007f}",
            ],
        ));
        let info = success(command(rust, &["info", path, "-p", "example"]));
        assert!(info.contains("9A2DB2E23F1504CD"));
        failure(command(rust, &["info", path, "-p", "incorrect"]));
        let without_password = command(rust, &["info", path]);
        let output = String::from_utf8_lossy(&without_password.stdout);
        assert!(output.contains("文件摘要：已校验（不提供认证）"));
        assert!(output.contains("\\u{B}\\u{7F}"));
        assert!(!output.contains("已解封并验证"));
        failure(without_password);
        if let Some(reference) = &reference {
            let name = format!("legacy-{algorithm}");
            success(command(
                reference,
                &[
                    "genkey",
                    "-o",
                    directory,
                    "-n",
                    &name,
                    "-m",
                    "Password",
                    "--algorithm",
                    algorithm,
                    "-p",
                    "example",
                    "--cek",
                    &"ab".repeat(32),
                    "--comment",
                    "中文 \"+😀\u{000b}\u{007f}",
                ],
            ));
            let legacy_cvk = temp.0.join(format!("{name}.cvk"));
            let native_cvk = temp.0.join(format!("migrated-{algorithm}.cvk"));
            success(command(
                rust,
                &[
                    "migrate",
                    legacy_cvk.to_str().unwrap(),
                    "-o",
                    native_cvk.to_str().unwrap(),
                    "-p",
                    "example",
                ],
            ));
            let info = success(command(
                rust,
                &["info", native_cvk.to_str().unwrap(), "-p", "example"],
            ));
            assert!(info.contains("9A2DB2E23F1504CD"));
        }
        let mut corrupt = fs::read(&cvk).unwrap();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        fs::write(&cvk, corrupt).unwrap();
        failure(command(rust, &["info", path, "-p", "example"]));
    }
}
