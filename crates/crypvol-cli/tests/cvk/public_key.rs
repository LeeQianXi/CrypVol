use std::path::Path;

use super::support::{TempDir, command, failure, make_key, reference, success};

#[test]
fn public_key_algorithms_and_legacy_migration() {
    let temp = TempDir::new();
    let directory = temp.0.to_str().unwrap();
    let rust = Path::new(env!("CARGO_BIN_EXE_crypvol-cli"));
    let reference = reference();
    let (rsa_private, rsa_public) = make_key(&temp.0, "rsa", None);
    for (algorithm, curve) in [
        ("RsaOaepSha256", None),
        ("RsaOaepSha384", None),
        ("RsaOaepSha512", None),
        ("EcdhP256", Some("ec_paramgen_curve:prime256v1")),
        ("EcdhP384", Some("ec_paramgen_curve:secp384r1")),
        ("EcdhP521", Some("ec_paramgen_curve:secp521r1")),
    ] {
        let (private, public) = if curve.is_some() {
            make_key(&temp.0, algorithm, curve)
        } else {
            (rsa_private.clone(), rsa_public.clone())
        };
        let private = private.to_str().unwrap();
        let public = public.to_str().unwrap();
        let rust_name = format!("native-{algorithm}");
        success(command(
            rust,
            &[
                "genkey",
                "-o",
                directory,
                "-n",
                &rust_name,
                "-m",
                "PublicKey",
                "--algorithm",
                algorithm,
                "--public-key",
                public,
                "--cek",
                &"ab".repeat(32),
                "--comment",
                "中文 \"+😀",
            ],
        ));
        let rust_cvk = temp.0.join(format!("{rust_name}.cvk"));
        let rust_cvk = rust_cvk.to_str().unwrap();
        let info = success(command(rust, &["info", rust_cvk, "--privkey-key", private]));
        assert!(info.contains("9A2DB2E23F1504CD"));

        if let Some(reference) = &reference {
            let legacy_name = format!("legacy-{algorithm}");
            success(command(
                reference,
                &[
                    "genkey",
                    "-o",
                    directory,
                    "-n",
                    &legacy_name,
                    "-m",
                    "PublicKey",
                    "--algorithm",
                    algorithm,
                    "--public-key",
                    public,
                    "--cek",
                    &"ab".repeat(32),
                    "--comment",
                    "中文 \"+😀",
                ],
            ));
            let legacy_cvk = temp.0.join(format!("{legacy_name}.cvk"));
            let migrated_cvk = temp.0.join(format!("migrated-{algorithm}.cvk"));
            success(command(
                rust,
                &[
                    "migrate",
                    legacy_cvk.to_str().unwrap(),
                    "-o",
                    migrated_cvk.to_str().unwrap(),
                    "--privkey-key",
                    private,
                ],
            ));
            let info = success(command(
                rust,
                &[
                    "info",
                    migrated_cvk.to_str().unwrap(),
                    "--privkey-key",
                    private,
                ],
            ));
            assert!(info.contains("9A2DB2E23F1504CD"));
        }
    }
}

#[test]
fn rejects_mismatched_key_types_and_curves_without_writing() {
    let temp = TempDir::new();
    let directory = temp.0.to_str().unwrap();
    let rust = Path::new(env!("CARGO_BIN_EXE_crypvol-cli"));
    let (_, rsa_public) = make_key(&temp.0, "rsa-mismatch", None);
    let (_, ec_public) = make_key(&temp.0, "ec-mismatch", Some("ec_paramgen_curve:secp384r1"));
    for (name, algorithm, public) in [
        ("wrong-type", "EcdhP256", rsa_public),
        ("wrong-curve", "EcdhP256", ec_public),
    ] {
        failure(command(
            rust,
            &[
                "genkey",
                "-o",
                directory,
                "-n",
                name,
                "-m",
                "PublicKey",
                "--algorithm",
                algorithm,
                "--public-key",
                public.to_str().unwrap(),
            ],
        ));
        assert!(!temp.0.join(format!("{name}.cvk")).exists());
    }
    let result = command(
        rust,
        &[
            "genkey", "-o", directory, "-n", "invalid", "--cek", "secret",
        ],
    );
    assert!(!result.status.success());
    assert!(!String::from_utf8_lossy(&result.stderr).contains("secret"));
    assert!(!temp.0.join("invalid.cvk").exists());
}
