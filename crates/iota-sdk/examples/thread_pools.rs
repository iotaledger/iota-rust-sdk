// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Thread Pools ===\n1.Sizing 2.Queues 3.Rejection\nCompleted!");
    Ok(())
}
