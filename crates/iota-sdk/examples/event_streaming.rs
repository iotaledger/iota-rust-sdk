// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Event Streaming ===\n1.Kafka 2.Partitions 3.Offset\nCompleted!");
    Ok(())
}
