// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Testing Frameworks ===\n1.Mocks 2.Fixtures 3.Assertions\nCompleted!");
    Ok(())
}
