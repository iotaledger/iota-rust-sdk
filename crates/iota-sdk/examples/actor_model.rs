// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Actor Model ===\n1.Messages 2.Mailboxes 3.Supervision\nCompleted!");
    Ok(())
}
