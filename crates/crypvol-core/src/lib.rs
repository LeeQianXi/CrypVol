//! CrypVol 核心库：CVP 数据卷格式、处理引擎、CVK 密钥信封与通用工具。
//!
//! 对外只暴露下层无关的能力；CLI 与 GUI 均通过本 crate 使用核心功能。

#![forbid(unsafe_code)]

pub mod crypto;
pub mod engine;
pub mod utility;
pub mod volume;
