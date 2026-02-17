// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Example: query coin metadata.
//!
//! Demonstrates how to inspect metadata for a given coin type.
//! Set COIN_TYPE (full struct tag) via env var.

use std::env::var;

use eyre::Result;
use iota_sdk::graphql_client::Client;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let coin_type = var("COIN_TYPE").unwrap_or_else(|_| "0x2::iota::IOTA".to_string());

    let metadata = client.coin_metadata(&coin_type).await?;

    match metadata {
        Some(m) => {
            println!("Coin type: {coin_type}");
            println!("Name: {:?}", m.name);
            println!("Symbol: {:?}", m.symbol);
            println!("Description: {:?}", m.description);
            println!("Decimals: {:?}", m.decimals);
            println!("Icon URL: {:?}", m.icon_url);
        }
        None => {
            println!("No metadata found for coin type: {coin_type}");
        }
    }

    Ok(())
}
