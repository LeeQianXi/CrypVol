//! 端到端密钥操作与参考程序互操作测试。

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

pub(super) struct TempDir(pub(super) PathBuf);

impl TempDir {
    pub(super) fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "crypvol-cvk-test-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(super) fn command(program: &Path, args: &[&str]) -> Output {
    Command::new(program).args(args).output().unwrap()
}

pub(super) fn success(output: Output) -> String {
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(!stdout.contains("未解封"), "{stdout}\n{stderr}");
    stdout
}

pub(super) fn failure(output: Output) {
    assert!(
        !output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

pub(super) fn reference() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("CRYPVOL_REFERENCE") {
        let path = PathBuf::from(path);
        assert!(path.is_file(), "CRYPVOL_REFERENCE 指向的文件不存在");
        return Some(path);
    }
    let path = PathBuf::from("/home/qianxi/.local/bin/CrypVol");
    path.is_file().then_some(path)
}

pub(super) fn make_key(directory: &Path, name: &str, curve: Option<&str>) -> (PathBuf, PathBuf) {
    let private = directory.join(format!("{name}.pem"));
    let public = directory.join(format!("{name}.pub"));
    let private_path = private.to_str().unwrap();
    let public_path = public.to_str().unwrap();
    let args = if let Some(curve) = curve {
        vec![
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            curve,
            "-out",
            private_path,
        ]
    } else {
        vec![
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            private_path,
        ]
    };
    success(command(Path::new("openssl"), &args));
    success(command(
        Path::new("openssl"),
        &["pkey", "-in", private_path, "-pubout", "-out", public_path],
    ));
    (private, public)
}
