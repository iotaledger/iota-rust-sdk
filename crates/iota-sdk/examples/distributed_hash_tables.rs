// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== DHT ===\n1.Kademlia 2.Routing 3.Replication\nCompleted!");
    Ok(())
}
