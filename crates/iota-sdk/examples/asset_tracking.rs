// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Asset Tracking Example ===\n");
    println!("1.Portfolio 2.Balances 3.Transfers 4.History\n");
    println!("Completed!");
    Ok(())
}
