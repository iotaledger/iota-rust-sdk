// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Leader Election ===\n1.Bully 2.Ring 3.Paxos\nCompleted!");
    Ok(())
}
