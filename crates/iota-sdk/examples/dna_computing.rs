// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== DNA Computing ===\n1.Molecular 2.DNA-storage 3.Computing\nCompleted!");
    Ok(())
}
