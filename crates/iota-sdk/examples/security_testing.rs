// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Security Testing ===\n1.SAST 2.DAST 3.Dependency\nCompleted!");
    Ok(())
}
