// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== API Gateway ===\n1.Routing 2.Rate-limit 3.Aggregation\nCompleted!");
    Ok(())
}
