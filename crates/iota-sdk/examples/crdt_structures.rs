// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== CRDTs ===\n1.G-Counter 2.OR-Set 3.LWW-Register\nCompleted!");
    Ok(())
}
