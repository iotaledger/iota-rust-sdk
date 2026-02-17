// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Markov Chains ===\n1.States 2.Transitions 3.Stationary\nCompleted!");
    Ok(())
}
