// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== L-Systems ===\n1.Grammars 2.Growth 3.Fractals\nCompleted!");
    Ok(())
}
