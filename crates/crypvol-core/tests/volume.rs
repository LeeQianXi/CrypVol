use crypvol_core::volume::{
    Fragment, IntegrityLevel, VolumeError, VolumeFooter, VolumeHeader, parse_block,
};

#[test]
fn reads_little_endian_cvp_header_and_block() {
    let mut bytes = [0; 263];
    bytes[..4].copy_from_slice(b"CVPH");
    bytes[4..12].copy_from_slice(&42_u64.to_le_bytes());
    bytes[12] = 0b0011_1011;
    bytes[13..17].copy_from_slice(&2_u32.to_le_bytes());
    bytes[17..25].copy_from_slice(&55_i64.to_le_bytes());
    bytes[25..30].copy_from_slice(b"a.txt");
    bytes[256..260].copy_from_slice(&3_i32.to_le_bytes());
    bytes[260..].copy_from_slice(b"abc");
    let (VolumeHeader::Plain(header), rest) = VolumeHeader::parse(&bytes).unwrap() else {
        panic!("expected plain header");
    };
    assert_eq!(
        (header.file_id, header.fragment_index, header.original_size),
        (42, 2, 55)
    );
    assert_eq!(header.path, "a.txt");
    assert_eq!(header.fragment, Fragment::CrossTail);
    assert_eq!(header.integrity, IntegrityLevel::Volume);
    assert!(header.gzip);
    assert_eq!(
        parse_block(rest).unwrap(),
        (b"abc".as_slice(), [].as_slice())
    );

    assert_eq!(
        VolumeHeader::parse(&bytes[..255]),
        Err(VolumeError::Truncated)
    );
    bytes[12] |= 4;
    assert_eq!(
        VolumeHeader::parse(&bytes),
        Err(VolumeError::UnsupportedFlags(bytes[12]))
    );
    assert_eq!(
        parse_block(&(-1_i32).to_le_bytes()),
        Err(VolumeError::InvalidSize)
    );
    assert_eq!(
        parse_block(&1_i32.to_le_bytes()),
        Err(VolumeError::Truncated)
    );
}

#[test]
fn reads_encrypted_cvp_header_and_footer_boundaries() {
    let mut bytes = [7; 284];
    bytes[..4].copy_from_slice(b"CVPE");
    let (VolumeHeader::Encrypted(header), rest) = VolumeHeader::parse(&bytes).unwrap() else {
        panic!("expected encrypted header");
    };
    assert_eq!(header.nonce, &[7; 12]);
    assert_eq!(header.ciphertext, &[7; 252]);
    assert_eq!(header.tag, &[7; 16]);
    assert!(rest.is_empty());
    assert_eq!(
        VolumeHeader::parse(&bytes[..283]),
        Err(VolumeError::Truncated)
    );

    let mut footer = [9; 37];
    footer[..4].copy_from_slice(b"CVPF");
    assert_eq!(VolumeFooter::parse(&footer[..36]).unwrap().sha256, [9; 32]);
    assert_eq!(VolumeFooter::parse(&footer), Err(VolumeError::InvalidSize));
}
