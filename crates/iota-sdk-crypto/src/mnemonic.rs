// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use bip39::Mnemonic;

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum MnemonicLength {
    Words12 = 12,
    Words24 = 24,
}

/// Generate a new BIP-39 mnemonic in English.
/// Supported word counts are 12 and 24 (default).
pub fn generate_mnemonic(word_count: impl Into<Option<MnemonicLength>>) -> String {
    let count = word_count.into().unwrap_or(MnemonicLength::Words24) as usize;
    Mnemonic::generate(count)
        .expect("mnemonic generation failed") // Safe to unwrap since the word count is controlled
        .to_string()
}
