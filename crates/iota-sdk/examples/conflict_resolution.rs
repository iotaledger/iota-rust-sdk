// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Conflict Resolution ===\n1.LWW 2.CRDTs 3.Consensus\nCompleted!");
    Ok(())
}
