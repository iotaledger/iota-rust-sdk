// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== DID ===\n1.DIDs 2.Verifiable-credentials 3.Schemas\nCompleted!");
    Ok(())
}
