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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_default_24_words() {
        let mnemonic = generate_mnemonic(None);
        let word_count = mnemonic.split_whitespace().count();
        assert_eq!(word_count, 24);
    }

    #[test]
    fn generate_12_words() {
        let mnemonic = generate_mnemonic(MnemonicLength::Words12);
        let word_count = mnemonic.split_whitespace().count();
        assert_eq!(word_count, 12);
    }

    #[test]
    fn generate_24_words_explicit() {
        let mnemonic = generate_mnemonic(MnemonicLength::Words24);
        let word_count = mnemonic.split_whitespace().count();
        assert_eq!(word_count, 24);
    }

    #[test]
    fn generated_mnemonic_is_valid_bip39() {
        let mnemonic_str = generate_mnemonic(None);
        // If parsing succeeds, the mnemonic is valid BIP-39
        assert!(
            bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &mnemonic_str).is_ok()
        );
    }

    #[test]
    fn two_generated_mnemonics_differ() {
        let m1 = generate_mnemonic(None);
        let m2 = generate_mnemonic(None);
        assert_ne!(m1, m2);
    }
}
