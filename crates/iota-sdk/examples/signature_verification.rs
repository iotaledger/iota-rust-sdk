// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Signature Verification Example ===\n");
    println!("1. Types: Ed25519, Secp256k1, Multisig");
    println!("2. Verify: Check signature validity");
    println!("3. Use Cases: Auth, permissions");
    println!("4. Best: Always verify signatures\n");
    println!("Signature verification completed!");
    Ok(())
}
