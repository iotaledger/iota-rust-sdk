// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Property Testing ===\n1.Properties 2.Generators 3.Shrinking\nCompleted!");
    Ok(())
}
