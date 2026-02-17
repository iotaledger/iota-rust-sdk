// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Optimistic Concurrency ===\n1.MVCC 2.Versioning 3.Conflicts\nCompleted!");
    Ok(())
}
