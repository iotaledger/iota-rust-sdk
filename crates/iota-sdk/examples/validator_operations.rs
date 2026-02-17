// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Example: Validator Operations
//!
//! This example demonstrates how to:
//! - Query active validators
//! - Get validator information
//! - Calculate staking rewards

use eyre::Result;
use iota_sdk::graphql_client::Client;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    println!("=== Validator Operations Example ===\n");

    // Step 1: Query active validators
    println!("1. Querying active validators...");
    let validators = client.active_validators(None, Default::default()).await?;
    println!("   Found {} active validators\n", validators.data.len());

    // Step 2: Display validator information
    println!("2. Validator Information:");
    for (idx, validator) in validators.data.iter().take(5).enumerate() {
        println!("\n   Validator #{}:", idx + 1);
        if let Some(name) = &validator.name {
            println!("     Name: {}", name);
        }
        println!("     Address: {}", validator.address.address);
        println!("     Voting Power: {}", validator.voting_power);

        if let Some(apy) = validator.next_epoch_stake_apy {
            println!("     Staking APY: {:.2}%", apy);
        }

        println!("     Pending Stake: {} MIST", validator.pending_stake);
        println!("     Pending Withdraw: {} MIST", validator.pending_withdraw);
    }

    // Step 3: Best practices for validator selection
    println!("\n3. Validator Selection Criteria:");
    println!("   - Check commission rates");
    println!("   - Review voting power distribution");
    println!("   - Consider uptime and performance");
    println!("   - Evaluate staking APY");
    println!("   - Assess community reputation\n");

    // Step 4: Staking workflow
    println!("4. Staking Workflow:");
    println!("   a. Choose a validator");
    println!("   b. Prepare staking transaction");
    println!("   c. Sign and submit transaction");
    println!("   d. Monitor staking rewards");
    println!("   e. Unstake when needed\n");

    println!("Validator operations example completed!");
    println!("See also: stake.rs, unstake.rs");

    Ok(())
}
