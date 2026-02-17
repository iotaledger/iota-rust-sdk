// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Replication ===\n1.Master-slave 2.Master-master 3.Multi-master\nCompleted!");
    Ok(())
}
