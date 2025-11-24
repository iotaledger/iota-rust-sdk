// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::crypto::mnemonic::MnemonicLength;

use crate::error::Result;

#[uniffi::remote(Enum)]
#[non_exhaustive]
pub enum MnemonicLength {
    Words12 = 12,
    Words24 = 24,
}

/// Generate a new BIP-39 mnemonic in English.
/// Supported word counts are 12 and 24 (default).
#[uniffi::export]
pub fn generate_mnemonic(word_count: Option<MnemonicLength>) -> String {
    iota_sdk::crypto::mnemonic::generate_mnemonic(word_count)
}
