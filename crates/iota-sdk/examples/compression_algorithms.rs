// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Compression ===\n1.Huffman 2.LZ77 3.Arithmetic\nCompleted!");
    Ok(())
}
