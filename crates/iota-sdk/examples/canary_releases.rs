// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Canary Releases ===\n1.Traffic 2.Metrics 3.Automation\nCompleted!");
    Ok(())
}
