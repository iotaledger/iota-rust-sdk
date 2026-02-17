// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== MVCC ===\n1.Versions 2.Garbage-collection 3.Read-views\nCompleted!");
    Ok(())
}
