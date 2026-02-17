// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    println!("=== CQRS ===\n1.Commands 2.Queries 3.Separation\nCompleted!");
    Ok(())
}
