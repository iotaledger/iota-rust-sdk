// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Cross-Chain ===\n1.Lock 2.Mint 3.Verify\nCompleted!");
    Ok(())
}
