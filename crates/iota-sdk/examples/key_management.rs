// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Example: key management with iota-sdk-crypto.
//!
//! Demonstrates a practical flow:
//! 1) generate a mnemonic
//! 2) derive Ed25519 and Secp256k1 private keys
//! 3) derive addresses from both keys
//! 4) print key/address metadata

use iota_sdk::{
    crypto::{
        FromMnemonic, ToFromBech32, ed25519::Ed25519PrivateKey,
        mnemonic::{MnemonicLength, generate_mnemonic}, secp256k1::Secp256k1PrivateKey,
    },
};

fn main() -> eyre::Result<()> {
    // 1) Generate mnemonic
    let mnemonic = generate_mnemonic(MnemonicLength::Words12);
    println!("Mnemonic: {mnemonic}");

    // 2) Derive private keys (deterministic from mnemonic)
    let ed25519_sk = Ed25519PrivateKey::from_mnemonic(&mnemonic, None, None)?;
    let secp256k1_sk = Secp256k1PrivateKey::from_mnemonic(&mnemonic, 0, None)?;

    // 3) Derive public keys + addresses
    let ed25519_pk = ed25519_sk.public_key();
    let secp256k1_pk = secp256k1_sk.public_key();

    let ed25519_address = ed25519_pk.derive_address();
    let secp256k1_address = secp256k1_pk.derive_address();

    // 4) Show metadata
    println!("\nEd25519");
    println!("- Private key (bech32): {}", ed25519_sk.to_bech32()?);
    println!("- Public key: {ed25519_pk}");
    println!("- Address: {ed25519_address}");

    println!("\nSecp256k1");
    println!("- Private key (bech32): {}", secp256k1_sk.to_bech32()?);
    println!("- Public key: {secp256k1_pk}");
    println!("- Address: {secp256k1_address}");

    Ok(())
}
