// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Rollups ===\n1.Optimistic 2.ZK 3.Hybrid\nCompleted!");
    Ok(())
}
