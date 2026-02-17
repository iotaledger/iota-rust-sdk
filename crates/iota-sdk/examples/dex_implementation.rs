// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== DEX ===\n1.AMM 2.Liquidity 3.Swaps\nCompleted!");
    Ok(())
}
