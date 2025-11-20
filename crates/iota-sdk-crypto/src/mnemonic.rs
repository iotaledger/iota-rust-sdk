// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use bip39::Mnemonic;

use crate::PrivateKeyError;

const DEFAULT_WORD_COUNT: usize = 24;

/// Generate a new BIP-39 mnemonic in English.
/// Supported word counts are 12, 15, 18, 21, and 24 (default).
pub fn generate_mnemonic(word_count: Option<usize>) -> Result<String, PrivateKeyError> {
    Ok(Mnemonic::generate(word_count.unwrap_or(DEFAULT_WORD_COUNT))?.to_string())
}
