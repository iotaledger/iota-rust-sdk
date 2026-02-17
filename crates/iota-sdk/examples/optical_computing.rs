// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Optical Computing ===\n1.Photonics 2.Interconnects 3.Processing\nCompleted!");
    Ok(())
}
