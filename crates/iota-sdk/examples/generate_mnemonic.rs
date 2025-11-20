// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_crypto::mnemonic::generate_mnemonic;

fn main() -> () {
    let mnemonic = generate_mnemonic(None);
    println!("Mnemonic: {mnemonic}");
}
