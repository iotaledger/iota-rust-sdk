// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// The number of words in a BIP-39 mnemonic.
#[derive(uniffi::Enum)]
pub enum MnemonicLength {
    Words12 = 12,
    Words24 = 24,
}

impl From<MnemonicLength> for iota_sdk::crypto::mnemonic::MnemonicLength {
    fn from(value: MnemonicLength) -> Self {
        match value {
            MnemonicLength::Words12 => Self::Words12,
            MnemonicLength::Words24 => Self::Words24,
        }
    }
}

/// Generate a new BIP-39 mnemonic in English.
/// Supported word counts are 12 and 24 (default).
#[uniffi::export]
pub fn generate_mnemonic(word_count: Option<MnemonicLength>) -> String {
    iota_sdk::crypto::mnemonic::generate_mnemonic(word_count.map(Into::into))
}
