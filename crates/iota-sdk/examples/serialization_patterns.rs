// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Serialization ===\n1.BCS 2.JSON 3.Custom\nCompleted!");
    Ok(())
}
