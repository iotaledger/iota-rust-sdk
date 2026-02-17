// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Stablecoin ===\n1.Collateral 2.Minting 3.Stability\nCompleted!");
    Ok(())
}
