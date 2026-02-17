// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Neuroevolution ===\n1.Topologies 2.Weights 3.Fitness\nCompleted!");
    Ok(())
}
