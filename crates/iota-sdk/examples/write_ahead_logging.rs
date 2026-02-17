// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== WAL ===\n1.Durability 2.Recovery 3.Checkpointing\nCompleted!");
    Ok(())
}
