// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Space-Based ===\n1.In-memory 2.Grid 3.Virtualization\nCompleted!");
    Ok(())
}
