use std::{fmt, str};

pub const PLAIN_HEADER_SIZE: usize = 256;
pub const ENCRYPTED_HEADER_SIZE: usize = 284;
pub const FOOTER_SIZE: usize = 36;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fragment {
    Full,
    CrossHead,
    CrossMid,
    CrossTail,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegrityLevel {
    None,
    Block,
    File,
    Volume,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryHeader<'a> {
    pub file_id: u64,
    pub fragment: Fragment,
    pub fragment_index: u32,
    pub original_size: u64,
    /// 归档内路径。提取时须另行校验目标路径。
    pub path: &'a str,
    pub integrity: IntegrityLevel,
    pub gzip: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptedHeader<'a> {
    pub nonce: &'a [u8; 12],
    pub ciphertext: &'a [u8; 252],
    pub tag: &'a [u8; 16],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeHeader<'a> {
    Plain(EntryHeader<'a>),
    Encrypted(EncryptedHeader<'a>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VolumeFooter {
    pub sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeError {
    Truncated,
    InvalidMagic,
    UnsupportedFlags(u8),
    InvalidSize,
    InvalidPath,
}

impl fmt::Display for VolumeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("CVP 记录截断"),
            Self::InvalidMagic => f.write_str("CVP 魔数无效"),
            Self::UnsupportedFlags(flags) => write!(f, "CVP 标志位不受支持：{flags:#04x}"),
            Self::InvalidSize => f.write_str("CVP 文件或块长度无效"),
            Self::InvalidPath => f.write_str("CVP 路径字段需要非空、以 NUL 结尾的 UTF-8"),
        }
    }
}

impl std::error::Error for VolumeError {}

impl<'a> VolumeHeader<'a> {
    /// 从当前记录边界读取条目头，返回条目头和剩余数据。
    pub fn parse(input: &'a [u8]) -> Result<(Self, &'a [u8]), VolumeError> {
        match input.get(..4).ok_or(VolumeError::Truncated)? {
            b"CVPH" => {
                let (header, rest) = input.split_first_chunk().ok_or(VolumeError::Truncated)?;
                Ok((Self::Plain(parse_plain(header)?), rest))
            }
            b"CVPE" => {
                let (header, rest) = input
                    .split_first_chunk::<ENCRYPTED_HEADER_SIZE>()
                    .ok_or(VolumeError::Truncated)?;
                let encrypted = EncryptedHeader {
                    nonce: header[4..16].try_into().unwrap(),
                    ciphertext: header[16..268].try_into().unwrap(),
                    tag: header[268..284].try_into().unwrap(),
                };
                Ok((Self::Encrypted(encrypted), rest))
            }
            _ => Err(VolumeError::InvalidMagic),
        }
    }
}

fn parse_plain(header: &[u8; PLAIN_HEADER_SIZE]) -> Result<EntryHeader<'_>, VolumeError> {
    let flags = header[12];
    if flags & 0b1100_0100 != 0 {
        return Err(VolumeError::UnsupportedFlags(flags));
    }
    let fragment = match flags & 3 {
        0 => Fragment::Full,
        1 => Fragment::CrossHead,
        2 => Fragment::CrossMid,
        _ => Fragment::CrossTail,
    };
    let integrity = match (flags >> 3) & 3 {
        0 => IntegrityLevel::None,
        1 => IntegrityLevel::Block,
        2 => IntegrityLevel::File,
        _ => IntegrityLevel::Volume,
    };

    let original_size = i64::from_le_bytes(header[17..25].try_into().unwrap());
    let original_size = u64::try_from(original_size).map_err(|_| VolumeError::InvalidSize)?;
    let path_field = &header[25..];
    let end = path_field
        .iter()
        .position(|&byte| byte == 0)
        .filter(|&end| end > 0)
        .ok_or(VolumeError::InvalidPath)?;
    let path = str::from_utf8(&path_field[..end]).map_err(|_| VolumeError::InvalidPath)?;

    Ok(EntryHeader {
        file_id: u64::from_le_bytes(header[4..12].try_into().unwrap()),
        fragment,
        fragment_index: u32::from_le_bytes(header[13..17].try_into().unwrap()),
        original_size,
        path,
        integrity,
        gzip: flags & 0x20 != 0,
    })
}

impl VolumeFooter {
    /// 解析恰好位于卷尾的 CVPF 记录。
    pub fn parse(input: &[u8]) -> Result<Self, VolumeError> {
        let (record, rest) = input
            .split_first_chunk::<FOOTER_SIZE>()
            .ok_or(VolumeError::Truncated)?;
        if &record[..4] != b"CVPF" {
            return Err(VolumeError::InvalidMagic);
        }
        if !rest.is_empty() {
            return Err(VolumeError::InvalidSize);
        }
        Ok(Self {
            sha256: record[4..].try_into().unwrap(),
        })
    }
}

/// 在已定位到块长字段时读取块记录，返回存储字节（含校验字段）和剩余数据。
pub fn parse_block(input: &[u8]) -> Result<(&[u8], &[u8]), VolumeError> {
    let (length, rest) = input.split_first_chunk().ok_or(VolumeError::Truncated)?;
    let size =
        usize::try_from(i32::from_le_bytes(*length)).map_err(|_| VolumeError::InvalidSize)?;
    rest.split_at_checked(size).ok_or(VolumeError::Truncated)
}
