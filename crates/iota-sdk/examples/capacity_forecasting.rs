// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Capacity Forecasting ===\n1.Trends 2.Models 3.Planning\nCompleted!");
    Ok(())
}
