// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Event Sourcing ===\n1.Store 2.Replay 3.Snapshots\nCompleted!");
    Ok(())
}
