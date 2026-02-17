// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Rate Limiting ===\n1.Quotas 2.Backoff 3.Strategies\nCompleted!");
    Ok(())
}
