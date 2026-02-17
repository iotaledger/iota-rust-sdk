// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Caching Algorithms ===\n1.LRU 2.LFU 3.ARC\nCompleted!");
    Ok(())
}
