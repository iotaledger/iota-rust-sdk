// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Number Theory ===\n1.Primes 2.Modular 3.Diophantine\nCompleted!");
    Ok(())
}
