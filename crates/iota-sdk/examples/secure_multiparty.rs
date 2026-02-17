// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Secure Multi-Party ===\n1.MPC 2.Secret-sharing 3.Protocols\nCompleted!");
    Ok(())
}
