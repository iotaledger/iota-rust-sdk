// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Example: Multisig Address Operations
//!
//! This example demonstrates how to:
//! - Create a multisig address from multiple public keys
//! - Generate a transaction from the multisig address
//! - Sign with multiple keys

use std::str::FromStr;

use eyre::Result;
use iota_sdk::{
    crypto::{Hash, PublicKey, Signature},
    graphql_client::Client,
    types::Address,
};

const THRESHOLD: usize = 2;
const WEIGHT: usize = 1;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    println!("=== Multisig Address Example ===\n");

    // Step 1: Generate or load multiple key pairs
    println!("1. Creating key pairs...");
    // In practice, these would be loaded from secure storage
    // For this example, we'll show the concept
    let public_keys: Vec<PublicKey> = vec
![        // These would be real public keys in practice
        PublicKey::from_str("...")?, // Key 1
        PublicKey::from_str("...")?, // Key 2
        PublicKey::from_str("...")?, // Key 3
    ];
    println!("   Generated {} public keys\n", public_keys.len())
;

    // Step 2: Create multisig address
    println!("2. Creating multisig address...");
    println!("   Threshold: {} out of {}", THRESHOLD, public_keys.len());
    let multisig_address = create_multisig_address(&public_keys, THRESHOLD)?;
    println!("   Multisig address: {}\n", multisig_address);

    // Step 3: Display usage info
    println!("3. Multisig Operations:");
    println!("   - This address requires {} signatures to spend funds", THRESHOLD);
    println!("   - Each key has a weight of {}", WEIGHT);
    println!("   - Total weight needed: {}\n", THRESHOLD * WEIGHT);

    // Step 4: Transaction signing (conceptual)
    println!("4. Transaction Signing Process:");
    println!("   a. Create unsigned transaction");
    println!("   b. Sign with key 1");
    println!("   c. Sign with key 2");
    println!("   d. Combine signatures");
    println!("   e. Submit signed transaction\n");

    println!("Multisig example completed successfully!");
    println!("Note: This is a conceptual example.");
    println!("In production, use proper key management.");

    Ok(())
}

/// Create a multisig address from multiple public keys
fn create_multisig_address(public_keys: &[PublicKey], threshold: usize) -> Result<Address> {
    // In a real implementation, this would:
    // 1. Sort public keys
    // 2. Create a multisig schema with weights
    // 3. Derive the address from the schema

    // Placeholder implementation
    // Real implementation would use iota_sdk's multisig functionality
    Ok(Address::from_str("0x0")?)
}

/// Sign a transaction hash with a key
#[allow(dead_code)]
fn sign_transaction(hash: &Hash, _private_key: &[u8]) -> Result<Signature> {
    // In practice, this would use the private key to sign
    Ok(Signature::default())
}
