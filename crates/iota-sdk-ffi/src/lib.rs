// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::wrong_self_convention,
    clippy::should_implement_trait,
    clippy::new_without_default
)]

use base64ct::Encoding;

mod macros;

#[cfg(feature = "crypto")]
pub mod crypto;
pub mod error;
pub mod graphql;
pub mod move_types;
pub mod transaction_builder;
pub mod types;

uniffi::setup_scaffolding!();

#[uniffi::export]
pub fn base64_encode(input: &[u8]) -> String {
    base64ct::Base64::encode_string(input)
}

#[uniffi::export]
pub fn base64_decode(input: String) -> crate::error::Result<Vec<u8>> {
    Ok(base64ct::Base64::decode_vec(&input)?)
}

#[uniffi::export]
pub fn hex_encode(input: &[u8]) -> String {
    hex::encode(input)
}

#[uniffi::export]
pub fn hex_decode(input: String) -> crate::error::Result<Vec<u8>> {
    Ok(hex::decode(input)?)
}

crate::export_primitive_types_bcs_conversion!(u8, u16, u32, u64, i8, i16, i32, i64, bool, String);
crate::export_primitive_types_json_conversion!(u8, u16, u32, u64, i8, i16, i32, i64, bool, String);
