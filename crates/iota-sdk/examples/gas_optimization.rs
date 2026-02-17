// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Example: Gas Optimization
//!
//! This example demonstrates how to:
//! - Understand gas costs in IOTA
//! - Optimize transaction gas usage
//! - Set appropriate gas budgets

use eyre::Result;
use iota_sdk::graphql_client::Client;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    println!("=== Gas Optimization Example ===\n");

    // Step 1: Understanding gas
    println!("1. Understanding Gas:");
    println!("   Components:");
    println!("   - Computation cost");
    println!("   - Storage cost");
    println!("   - Storage rebate (refund)\n");
    println!("   Gas is measured in MIST");
    println!("   1 IOTA = 10^9 MIST\n");

    // Step 2: Gas budgeting
    println!("2. Gas Budgeting:");
    println!("   Setting gas budget:");
    println!("   - Too low: Transaction fails");
    println!("   - Too high: Worry about safety");
    println!("   - Just right: Estimate + buffer\n");
    println!("   Best practice:");
    println!("   - Use dry_run to estimate");
    println!("   - Add 10-20% buffer");
    println!("   - Monitor actual usage\n");

    // Step 3: Optimization strategies
    println!("3. Optimization Strategies:");
    println!("   a. Batch operations");
    println!("      - Combine multiple transfers");
    println!("      - Use PTB effectively\n");
    println!("   b. Minimize object creation");
    println!("      - Reuse objects when possible");
    println!("      - Delete unused objects\n");
    println!("   c. Efficient Move code");
    println!("      - Avoid unnecessary loops");
    println!("      - Use efficient data structures\n");

    // Step 4: Storage optimization
    println!("4. Storage Optimization:");
    println!("   - Storage costs persist");
    println!("   - Delete objects to get rebate");
    println!("   - Keep object size small");
    println!("   - Use dynamic fields wisely\n");

    // Step 5: Common patterns
    println!("5. Gas-Efficient Patterns:");
    println!("   - Coin management:");
    println!("     * Merge small coins");
    println!("     * Split large coins strategically\n");
    println!("   - Transaction batching:");
    println!("     * Combine related operations");
    println!("     * Use programmable transactions\n");

    // Step 6: Monitoring and analysis
    println!("6. Monitoring Gas Usage:");
    println!("   - Use dry_run for estimates");
    println!("   - Check transaction effects");
    println!("   - Track gas over time");
    println!("   - Profile expensive operations\n");

    // Step 7: Best practices
    println!("7. Best Practices:");
    println!("   - Always test with dry_run");
    println!("   - Set realistic gas budgets");
    println!("   - Optimize hot paths");
    println!("   - Balance cost vs complexity");
    println!("   - Monitor mainnet gas prices\n");

    println!("Gas optimization example completed!");
    println!("See also: gas_sponsor.rs, gas_station.rs");

    Ok(())
}
