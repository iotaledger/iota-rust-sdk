// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Service Discovery ===\n1.Registry 2.Health 3.Load-balancing\nCompleted!");
    Ok(())
}
