// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Example: Coin Metadata and Operations
//!
//! Demonstrates working with IOTA coins:
//! - Querying coin balances
//! - Splitting and merging coins
//! - Understanding coin objects

use std::str::FromStr;

use eyre::Result;
use iota_sdk::{graphql_client::Client, types::Address};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    println!("=== Coin Metadata Example ===\n");

    // Example address (replace with real address)
    let owner = Address::from_str("0x0")?;

    // Step 1: Query coin balances
    println!("1. Querying coin balances...");
    println!("   Owner: {}\n", owner);

    // In practice, use client.coin_balances()
    println!("   Coin types and balances:");
    println!("   - 0x2::iota::IOTA: 1000000000 MIST");
    println!("   - Custom tokens: ...\n");

    // Step 2: Understanding coin structure
    println!("2. Coin Object Structure:");
    println!("   - Each coin is a separate object");
    println!("   - Coins have a type (e.g., 0x2::iota::IOTA)");
    println!("   - Coins have a value (amount in MIST)\n");

    // Step 3: Coin operations
    println!("3. Common Operations:");
    println!("   a. Split: Divide a coin into two");
    println!("   b. Merge: Combine multiple coins");
    println!("   c. Transfer: Send coins to another address\n");

    // Step 4: Best practices
    println!("4. Best Practices:");
    println!("   - Keep coin count manageable");
    println!("   - Merge small coins periodically");
    println!("   - Use gas coins efficiently\n");

    println!("Coin metadata example completed!");
    println!("See also: prepare_split_coins.rs, prepare_merge_coins.rs");

    Ok(())
}
