#[cfg(unix)]
use std::fs;
use std::{path::Path, process::Command};

#[cfg(unix)]
use super::support::failure;
use super::support::{TempDir, command, success};

#[test]
fn concurrent_rekey_preserves_both_changes() {
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
            "concurrent",
            "-m",
            "Password",
            "-p",
            "example",
        ],
    ));
    let cvk = temp.0.join("concurrent.cvk");
    let path = cvk.to_str().unwrap();
    let mut children = Vec::new();
    for (option, value) in [("--label", "first"), ("--description", "second")] {
        children.push(
            Command::new(rust)
                .args([
                    "rekey",
                    path,
                    "-p",
                    "example",
                    option,
                    value,
                    "--backup=false",
                ])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        );
    }
    for child in children {
        success(child.wait_with_output().unwrap());
    }
    let info = success(command(rust, &["info", path, "-p", "example"]));
    assert!(info.contains("标签：first"), "{info}");
    assert!(info.contains("描述：second"), "{info}");
}

#[cfg(unix)]
#[test]
fn output_symlink_to_backup_cannot_replace_backup() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new();
    let directory = temp.0.to_str().unwrap();
    let rust = Path::new(env!("CARGO_BIN_EXE_crypvol-cli"));
    success(command(rust, &["genkey", "-o", directory, "-n", "key"]));
    let source = temp.0.join("key.cvk");
    let backup = temp.0.join("key.cvk.bak");
    let alias = temp.0.join("alias.cvk");
    let original = fs::read(&source).unwrap();
    symlink(&backup, &alias).unwrap();
    failure(command(
        rust,
        &[
            "rekey",
            source.to_str().unwrap(),
            "--output",
            alias.to_str().unwrap(),
        ],
    ));
    assert_eq!(fs::read(&source).unwrap(), original);
    assert_eq!(fs::read(&backup).unwrap(), original);
}
