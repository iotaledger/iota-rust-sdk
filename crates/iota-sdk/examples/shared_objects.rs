// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Example: Shared Object Operations
//!
//! This example demonstrates how to:
//! - Understand shared vs owned objects
//! - Query shared objects
//! - Work with shared objects in transactions

use eyre::Result;
use iota_sdk::graphql_client::Client;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    println!("=== Shared Object Operations Example ===\n");

    // Step 1: Understanding shared objects
    println!("1. Shared Objects Overview:");
    println!("   - Shared objects can be accessed by anyone");
    println!("   - Multiple transactions can use them concurrently");
    println!("   - Require special handling in transactions");
    println!("   - Examples: pools, registries, shared state\n");

    // Step 2: Differences from owned objects
    println!("2. Shared vs Owned Objects:");
    println!("   Owned Objects:");
    println!("     - Single owner controls access");
    println!("     - Only owner can use in transactions");
    println!("     - Simpler transaction handling\n");
    println!("   Shared Objects:");
    println!("     - No single owner");
    println!("     - Anyone can use them");
    println!("     - Requires shared object references\n");

    // Step 3: Querying shared objects
    println!("3. Querying Shared Objects:");
    println!("   - Use object() to fetch object details");
    println!("   - Check if object has shared ownership");
    println!("   - Identify object type and structure\n");

    // Step 4: Transaction patterns
    println!("4. Transaction Patterns with Shared Objects:");
    println!("   a. Move call with shared object");
    println!("   b. Multiple shared objects in one transaction");
    println!("   c. Mixing shared and owned objects");
    println!("   d. Best practices for concurrency\n");

    // Step 5: Common use cases
    println!("5. Common Use Cases:");
    println!("   - DEX liquidity pools");
    println!("   - Shared registries");
    println!("   - Governance contracts");
    println!("   - Public counters/state\n");

    // Step 6: Best practices
    println!("6. Best Practices:");
    println!("   - Minimize shared object usage");
    println!("   - Design for concurrent access");
    println!("   - Handle contention gracefully");
    println!("   - Consider gas costs\n");

    println!("Shared objects example completed!");
    println!("See also: transactions_with_shared.rs, dynamic_fields.rs");

    Ok(())
}
