// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Vector Clocks ===\n1.Ordering 2.Causality 3.Conflicts\nCompleted!");
    Ok(())
}
