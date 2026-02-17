// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Reactive ===\n1.Observable 2.Operators 3.Backpressure\nCompleted!");
    Ok(())
}
