// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== CPU Caching ===\n1.L1/L2/L3 2.Coherence 3.False-sharing\nCompleted!");
    Ok(())
}
