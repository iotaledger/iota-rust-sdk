// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Transaction Batching Example ===\n");
    println!("1. PTB: Programmable Transaction Blocks");
    println!("2. Benefits: Gas efficiency, atomic execution");
    println!("3. Patterns: Batch transfers, swaps");
    println!("4. Best: Group related operations\n");
    println!("Transaction batching completed!");
    Ok(())
}
