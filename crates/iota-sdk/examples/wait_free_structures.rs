// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Wait-Free ===\n1.Guarantees 2.Complexity 3.Tradeoffs\nCompleted!");
    Ok(())
}
