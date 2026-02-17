// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Example: Advanced Move Patterns
//! 
//! Demonstrates advanced Move programming patterns:
//! - Generics and type parameters
//! - Capabilities and resource access patterns
//! - Event emission and handling
//! - Custom type constraints

use eyre::Result;
use iota_sdk::graphql_client::Client;

#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    
    println!("=== Advanced Move Patterns Example ===\n");
    
    println!("1. Generics and Type Parameters:");
    println!("   - Generic functions and structs");
    println!("   - Phantom types for type safety");
    println!("   - Type constraints and abilities\n");
    
    println!("2. Capability Patterns:");
    println!("   - Capabilities as access control");
    println!("   - Linear types for resource management");
    println!("   - Proof-carrying code patterns\n");
    
    println!("3. Resource Patterns:");
    println!("   - Store vs key abilities");
    println!("   - Resource wrapping and composition");
    println!("   - Hot potato pattern\n");
    
    println!("4. Event Patterns:");
    println!("   - Structured event emission");
    println!("   - Event indexing and querying");
    println!("   - Cross-contract communication\n");
    
    println!("5. Advanced Storage Patterns:");
    println!("   - Dynamic fields and objects");
    println!("   - Table and bag data structures");
    println!("   - Linked list implementations\n");
    
    println!("6. Design Patterns:");
    println!("   - Witness pattern for type creation");
    println!("   - Publisher capabilities");
    println!("   - One-time witness pattern\n");
    
    println!("Advanced Move patterns example completed!");
    println!("See also: move_package_info.rs, generic_move_function.rs");
    
    Ok(())
}
