// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Coding Theory ===\n1.Error-correction 2.Reed-Solomon 3.LDPC\nCompleted!");
    Ok(())
}
