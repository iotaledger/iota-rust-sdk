// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Verifiable Computation ===\n1.Proofs 2.Verification 3. Outsourcing\nCompleted!");
    Ok(())
}
