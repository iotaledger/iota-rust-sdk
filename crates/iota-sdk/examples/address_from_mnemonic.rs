// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use base64ct::{Base64, Encoding};
use iota_crypto::{
    FromMnemonic, ToFromBech32, ed25519::Ed25519PrivateKey, secp256k1::Secp256k1PrivateKey,
    secp256r1::Secp256r1PrivateKey,
};
use iota_types::PublicKeyExt;

const MNEMONIC: &str = "round attack kitchen wink winter music trip tiny nephew hire orange what";

fn main() -> eyre::Result<()> {
    let private_key = Ed25519PrivateKey::from_mnemonic(MNEMONIC, None, None)?;
    let private_key_bech32 = private_key.to_bech32().unwrap();
    let public_key = private_key.public_key();
    let flagged_public_key = Base64::encode_string(&public_key.to_flagged_bytes());
    let address = public_key.derive_address();

    println!("Ed25519\n---");
    println!("Private Key: {private_key_bech32}");
    println!("Public Key: {public_key}");
    println!("Public Key With Flag: {flagged_public_key}");
    println!("Address: {address}");

    let private_key = Secp256k1PrivateKey::from_mnemonic(MNEMONIC, None, None)?;
    let private_key_bech32 = private_key.to_bech32().unwrap();
    let public_key = private_key.public_key();
    let flagged_public_key = Base64::encode_string(&public_key.to_flagged_bytes());
    let address = public_key.derive_address();

    println!("\nSecp256k1\n---");
    println!("Private Key: {private_key_bech32}");
    println!("Public Key: {public_key}");
    println!("Public Key With Flag: {flagged_public_key}");
    println!("Address: {address}");

    let private_key = Secp256r1PrivateKey::from_mnemonic(MNEMONIC, None, None)?;
    let private_key_bech32 = private_key.to_bech32().unwrap();
    let public_key = private_key.public_key();
    let flagged_public_key = Base64::encode_string(&public_key.to_flagged_bytes());
    let address = public_key.derive_address();

    println!("\nSecp256r1\n---");
    println!("Private Key: {private_key_bech32}");
    println!("Public Key: {public_key}");
    println!("Public Key With Flag: {flagged_public_key}");
    println!("Address: {address}");

    Ok(())
}
