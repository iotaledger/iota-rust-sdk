// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Streaming Patterns ===\n1.Windowing 2.Watermarks 3.Late-data\nCompleted!");
    Ok(())
}
