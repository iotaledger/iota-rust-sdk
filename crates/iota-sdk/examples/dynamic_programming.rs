// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== DP ===\n1.Overlapping 2.Optimal 3.Memoization\nCompleted!");
    Ok(())
}
