// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== FPGA ===\n1.HDL 2.Synthesis 3.Bitstreams\nCompleted!");
    Ok(())
}
