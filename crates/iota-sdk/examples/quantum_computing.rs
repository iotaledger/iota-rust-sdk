// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Quantum Computing ===\n1.Qubits 2.Gates 3.Algorithms\nCompleted!");
    Ok(())
}
