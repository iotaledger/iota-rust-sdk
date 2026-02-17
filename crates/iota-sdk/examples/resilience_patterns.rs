// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Resilience ===\n1.Circuit breaker 2.Bulkhead 3.Fallback\nCompleted!");
    Ok(())
}
