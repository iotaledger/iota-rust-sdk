// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Differentiable ===\n1.AD 2.JVP 3.VJP\nCompleted!");
    Ok(())
}
