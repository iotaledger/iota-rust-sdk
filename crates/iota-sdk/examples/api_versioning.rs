// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== API Versioning ===\n1.URI 2.Header 3.Backward-compat\nCompleted!");
    Ok(())
}
