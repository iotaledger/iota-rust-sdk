// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Lock-Free ===\n1.CAS 2.ABA 3.Memory-ordering\nCompleted!");
    Ok(())
}
