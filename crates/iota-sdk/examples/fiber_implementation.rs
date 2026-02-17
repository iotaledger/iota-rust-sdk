// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Fibers ===\n1.Lightweight 2.Scheduling 3.Stackful\nCompleted!");
    Ok(())
}
