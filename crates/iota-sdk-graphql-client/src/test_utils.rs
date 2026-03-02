// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Test utilities shared across the crate.

use crate::Client;

/// Number of coins expected from a faucet request.
pub const NUM_COINS_FROM_FAUCET: usize = 5;

/// Create a test client based on the NETWORK environment variable.
pub fn test_client() -> Client {
    let network = std::env::var("NETWORK").unwrap_or_else(|_| "local".to_string());
    match network.as_str() {
        "mainnet" => Client::new_mainnet(),
        "testnet" => Client::new_testnet(),
        "devnet" => Client::new_testnet(),
        "local" => Client::new_localnet(),
        _ => Client::new(&network).expect("Invalid network URL: {network}"),
    }
}
