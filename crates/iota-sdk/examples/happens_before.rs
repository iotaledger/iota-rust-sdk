// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Happens-Before ===\n1.Synchronizes-with 2.Program-order 3.DRFO\nCompleted!");
    Ok(())
}
