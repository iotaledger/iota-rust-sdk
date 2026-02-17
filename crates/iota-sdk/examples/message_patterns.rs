// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Message Patterns ===\n1.Queue 2.Pub-sub 3.Routing\nCompleted!");
    Ok(())
}
