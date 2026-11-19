//! CVK 密钥信封：保护模式、密钥体与 CEK 解封。

mod cvk;

pub use cvk::*;

mod document;
pub use document::*;

mod public_key;
pub use public_key::{
    load_private_key, load_public_key, private_key_requires_password, unlock_with_private_key,
    unlock_with_private_key_aad,
};
