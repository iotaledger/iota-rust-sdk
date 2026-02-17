// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== DDD Patterns ===\n1.Aggregates 2.Bounded-contexts 3.Events\nCompleted!");
    Ok(())
}
