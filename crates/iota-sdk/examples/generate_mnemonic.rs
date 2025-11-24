// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_crypto::mnemonic::{MnemonicWordCount, generate_mnemonic};

fn main() {
    let mnemonic = generate_mnemonic(None);
    println!("24 word mnemonic: {mnemonic}");
    let mnemonic = generate_mnemonic(MnemonicWordCount::Words12);
    println!("12 word mnemonic: {mnemonic}");
}
