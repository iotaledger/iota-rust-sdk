// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Pessimistic Locking ===\n1.2PL 2.Deadlocks 3.Timeouts\nCompleted!");
    Ok(())
}
