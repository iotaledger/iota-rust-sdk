// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Test utilities shared across the crate.

use crate::GraphQLClient;

/// Number of coins expected from a faucet request.
pub const NUM_COINS_FROM_FAUCET: usize = 5;

/// Create a test client based on the NETWORK environment variable.
pub fn test_client() -> GraphQLClient {
    let network = std::env::var("NETWORK").unwrap_or_else(|_| "local".to_string());
    match network.as_str() {
        "mainnet" => GraphQLClient::new_mainnet().unwrap(),
        "testnet" => GraphQLClient::new_testnet().unwrap(),
        "devnet" => GraphQLClient::new_devnet().unwrap(),
        "local" => GraphQLClient::new_localnet().unwrap(),
        _ => GraphQLClient::new(&network).expect("Invalid network URL: {network}"),
    }
}
