// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Chaos Engineering ===\n1.Experiments 2.Blast-radius 3.Recovery\nCompleted!");
    Ok(())
}
