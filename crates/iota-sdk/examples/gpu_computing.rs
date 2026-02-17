// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== GPU Computing ===\n1.CUDA 2.OpenCL 3.Compute-shaders\nCompleted!");
    Ok(())
}
