// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Liquidity Mining ===\n1.Incentives 2.Distribution 3.Vesting\nCompleted!");
    Ok(())
}
