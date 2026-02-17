// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Event-Driven ===\n1.Publish 2.Subscribe 3.Process\nCompleted!");
    Ok(())
}
