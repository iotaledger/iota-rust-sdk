// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use base64ct::{Base64, Encoding};
use iota_crypto::{ToFromBech32, ed25519::Ed25519PrivateKey};
use iota_types::PublicKeyExt;
use rand::rngs::OsRng;

fn main() {
    let private_key = Ed25519PrivateKey::generate(OsRng);
    let private_key_bech32 = private_key.to_bech32().unwrap();
    let public_key = private_key.public_key();
    let flagged_public_key = Base64::encode_string(&public_key.to_flagged_bytes());
    let address = public_key.derive_address();

    println!("Private Key: {private_key_bech32}");
    println!("Public Key: {public_key}");
    println!("Public Key With Flag: {flagged_public_key}");
    println!("Address: {address}");
}
