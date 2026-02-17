// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Quantum Resistance ===\n1.Post-quantum 2.Lattice-based 3.Hash-based\nCompleted!");
    Ok(())
}
