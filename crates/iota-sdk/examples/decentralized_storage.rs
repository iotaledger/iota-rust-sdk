// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Decentralized Storage ===\n1.IPFS 2.Filecoin 3.Arweave\nCompleted!");
    Ok(())
}
