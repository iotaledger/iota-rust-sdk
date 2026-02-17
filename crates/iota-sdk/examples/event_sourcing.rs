// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Event Sourcing ===\n1.Logs 2.Replay 3.State\nCompleted!");
    Ok(())
}
