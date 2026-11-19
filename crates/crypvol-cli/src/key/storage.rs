use std::{
    fs::{self, File},
    io::{self, Write},
    path::Path,
};

use tempfile::NamedTempFile;

/// 等待源文件锁，避免在其他重封装替换路径后继续使用旧文件。
pub(super) fn lock_source(path: &Path) -> io::Result<File> {
    for _ in 0..16 {
        let file = File::open(path)?;
        file.lock()?;
        let locked = same_file::Handle::from_file(file.try_clone()?)?;
        let current = same_file::Handle::from_path(path)?;
        if locked == current {
            return Ok(file);
        }
    }
    Err(io::Error::other("源文件被反复替换，请重试"))
}

/// 在目标目录中写入并同步临时文件，再保存到目标路径。
fn temporary_file(path: &Path, data: &[u8]) -> io::Result<NamedTempFile> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".crypvol-")
        .tempfile_in(parent)?;
    temporary.write_all(data)?;
    temporary.as_file().sync_all()?;
    Ok(temporary)
}

pub(crate) fn create(path: &Path, data: &[u8]) -> io::Result<()> {
    temporary_file(path, data)?
        .persist_noclobber(path)
        .map_err(|error| error.error)?;
    Ok(())
}

pub(super) fn replace(path: &Path, data: &[u8]) -> io::Result<()> {
    temporary_file(path, data)?
        .persist(path)
        .map_err(|error| error.error)?;
    Ok(())
}
