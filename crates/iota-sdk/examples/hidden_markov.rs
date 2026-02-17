// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== HMM ===\n1.States 2.Observations 3.Decoding\nCompleted!");
    Ok(())
}
