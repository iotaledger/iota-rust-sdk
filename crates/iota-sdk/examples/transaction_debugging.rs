// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Example: Transaction Debugging
//!
//! This example demonstrates how to:
//! - Debug transaction failures
//! - Use dry run for testing
//! - Handle common errors

use eyre::Result;
use iota_sdk::graphql_client::Client;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    println!("=== Transaction Debugging Example ===\n");

    // Step 1: Common transaction errors
    println!("1. Common Transaction Errors:");
    println!("   - Insufficient gas");
    println!("   - Object not found");
    println!("   - Invalid object version");
    println!("   - Permission denied");
    println!("   - Move abort");
    println!("   - Type mismatch\n");

    // Step 2: Using dry run
    println!("2. Using Dry Run:");
    println!("   Purpose:");
    println!("   - Test transactions before submission");
    println!("   - Estimate gas costs");
    println!("   - Check for errors safely");
    println!("   - Validate transaction logic\n");
    println!("   Usage:");
    println!("   a. Build transaction");
    println!("   b. Call dry_run()");
    println!("   c. Check error field");
    println!("   d. Review gas usage\n");

    // Step 3: Error interpretation
    println!("3. Error Interpretation:");
    println!("   - Read error messages carefully");
    println!("   - Check abort codes in Move");
    println!("   - Verify object ownership");
    println!("   - Validate type parameters");
    println!("   - Check gas budget\n");

    // Step 4: Debugging strategies
    println!("4. Debugging Strategies:");
    println!("   a. Start with dry run");
    println!("   b. Check object states");
    println!("   c. Verify sender address");
    println!("   d. Inspect transaction effects");
    println!("   e. Use dev inspect for Move calls\n");

    // Step 5: Transaction inspection
    println!("5. Transaction Inspection:");
    println!("   - Use get_transaction()");
    println!("   - Check transaction status");
    println!("   - Review effects and events");
    println!("   - Examine object changes\n");

    // Step 6: Best practices
    println!("6. Best Practices:");
    println!("   - Always dry run first");
    println!("   - Set appropriate gas budget");
    println!("   - Handle errors gracefully");
    println!("   - Log transaction digests");
    println!("   - Test incrementally\n");

    println!("Transaction debugging example completed!");
    println!("See also: dry_run_bytes.rs, dev_inspect.rs, get_transaction.rs");

    Ok(())
}
