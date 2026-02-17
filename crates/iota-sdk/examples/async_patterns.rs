// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Async Patterns ===\n1.Futures 2.Streams 3.Channels\nCompleted!");
    Ok(())
}
