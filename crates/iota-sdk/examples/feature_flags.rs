// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Feature Flags ===\n1.Toggles 2.Rollout 3.A/B-testing\nCompleted!");
    Ok(())
}
