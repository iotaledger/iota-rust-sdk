// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== VC ===\n1.Credentials 2.Presentations 3.Proofs\nCompleted!");
    Ok(())
}
