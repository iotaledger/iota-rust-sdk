// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Consensus ===\n1.Raft 2.Paxos 3.Zab\nCompleted!");
    Ok(())
}
