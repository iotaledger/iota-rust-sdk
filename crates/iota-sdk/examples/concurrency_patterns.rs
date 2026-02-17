// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Concurrency ===\n1.Async 2.Locking 3.Coordination\nCompleted!");
    Ok(())
}
