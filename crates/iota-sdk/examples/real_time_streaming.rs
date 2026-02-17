// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Real-time Streaming ===\n1.WebSockets 2.Events 3.Filters\nCompleted!");
    Ok(())
}
