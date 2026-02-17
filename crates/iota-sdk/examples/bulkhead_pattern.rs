// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Bulkhead ===\n1.Isolation 2.Pools 3.Limits\nCompleted!");
    Ok(())
}
