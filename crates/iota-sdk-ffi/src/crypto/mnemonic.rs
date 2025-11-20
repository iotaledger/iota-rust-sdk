// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::error::Result;

/// Generate a new BIP-39 mnemonic in English.
/// Supported word counts are 12, 15, 18, 21, and 24 (default).
#[uniffi::export]
pub fn generate_mnemonic(word_count: Option<u32>) -> Result<String> {
    let word_count = word_count.map(|w| w as usize);
    Ok(iota_sdk::crypto::mnemonic::generate_mnemonic(word_count)?)
}
