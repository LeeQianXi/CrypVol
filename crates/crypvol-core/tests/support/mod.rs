use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

pub fn cvk(header: &[u8], body: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(body)
    ));
    let mut bytes = b"CVK1".to_vec();
    bytes.extend((header.len() as u32).to_le_bytes());
    bytes.extend((body.len() as u32).to_le_bytes());
    bytes.extend(32_u32.to_le_bytes());
    bytes.extend(header);
    bytes.extend(body);
    bytes.extend(digest);
    bytes
}
