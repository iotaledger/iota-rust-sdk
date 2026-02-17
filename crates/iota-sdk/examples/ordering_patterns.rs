// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Ordering ===\n1.Sequence 2.Timestamp 3.Causality\nCompleted!");
    Ok(())
}
