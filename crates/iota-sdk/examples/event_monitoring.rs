// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Example: Event Monitoring
//!
//! This example demonstrates how to:
//! - Query blockchain events
//! - Filter events by criteria
//! - Monitor specific events for applications

use eyre::Result;
use iota_sdk::graphql_client::Client;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    println!("=== Event Monitoring Example ===\n");

    // Step 1: Understanding events
    println!("1. Events in IOTA:");
    println!("   - Events are emitted by Move functions");
    println!("   - Used to track on-chain activities");
    println!("   - Essential for building reactive apps");
    println!("   - Can be filtered and queried\n");

    // Step 2: Event structure
    println!("2. Event Structure:");
    println!("   - Event type (module::event_name)");
    println!("   - Sender address");
    println!("   - Timestamp");
    println!("   - Event data (BCS encoded)\n");

    // Step 3: Querying events
    println!("3. Querying Events:");
    println!("   Methods:");
    println!("   a. By transaction digest");
    println!("   b. By event type");
    println!("   c. By sender address");
    println!("   d. By time range");
    println!("   e. With pagination\n");

    // Step 4: Filtering strategies
    println!("4. Filtering Strategies:");
    println!("   - Filter by package ID");
    println!("   - Filter by module");
    println!("   - Filter by event type");
    println!("   - Combine multiple filters\n");

    // Step 5: Common patterns
    println!("5. Common Monitoring Patterns:");
    println!("   - Watch for token transfers");
    println!("   - Monitor staking events");
    println!("   - Track DEX trades");
    println!("   - Listen for governance events\n");

    // Step 6: Best practices
    println!("6. Best Practices:");
    println!("   - Use pagination for large result sets");
    println!("   - Cache event data locally");
    println!("   - Handle event ordering carefully");
    println!("   - Consider checkpoint-based monitoring");
    println!("   - Implement retry logic\n");

    // Step 7: Use cases
    println!("7. Real-World Use Cases:");
    println!("   - Portfolio tracking applications");
    println!("   - Notification systems");
    println!("   - Analytics dashboards");
    println!("   - Event-driven architectures\n");

    println!("Event monitoring example completed!");
    println!("See also: package_events.rs, get_transaction.rs");

    Ok(())
}
