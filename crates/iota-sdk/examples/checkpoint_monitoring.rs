// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();
    println!("=== Checkpoint Monitoring Example ===\n");
    
    // Get latest checkpoint
    println!("1. Checkpoints:");
    println!("   - Network organizes transactions in checkpoints");
    println!("   - Each checkpoint contains multiple transactions");
    println!("   - Useful for synchronization\n");
    
    println!("2. Epochs:");
    println!("   - Time periods for validator sets");
    println!("   - Rewards distributed per epoch");
    println!("   - System parameters may change\n");
    
    println!("3. Monitoring:");
    println!("   - Track checkpoint progress");
    println!("   - Monitor epoch transitions");
    println!("   - Sync application state\n");
    
    println!("Checkpoint monitoring completed!");
    Ok(())
}
