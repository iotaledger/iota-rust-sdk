// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use base64ct::{Base64, Encoding};
use iota_crypto::ed25519::Ed25519PrivateKey;
use rand::rngs::OsRng;

fn main() {
    let private_key = Ed25519PrivateKey::generate(OsRng);
    let private_key_bech32 = private_key.to_bech32().unwrap();
    let public_key = private_key.public_key();
    let address = public_key.derive_address();

    let mut flagged_public_key = vec![public_key.scheme().to_u8()];
    flagged_public_key.extend_from_slice(public_key.as_bytes());
    let encoded_public_key = Base64::encode_string(&flagged_public_key);

    println!("Private Key: {private_key_bech32}");
    println!("Public Key: {public_key}");
    println!("Public Key With Flag: {encoded_public_key}");
    println!("Address: {address}");
}
