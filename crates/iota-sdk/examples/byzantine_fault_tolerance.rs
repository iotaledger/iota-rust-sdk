// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== BFT ===\n1.PBFT 2.Tendermint 3.HotStuff\nCompleted!");
    Ok(())
}
