// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use iota_sdk_graphql_client_next::{GraphQLClient, iota_types::Transaction};

#[tokio::main]
async fn main() -> Result<()> {
    let client = GraphQLClient::testnet()?;

    let tx_bytes_base64 = "AAABACAAAKSYS9SV1DRvogjd/09dXlrUjCHexjHd68mYCfFpAAEBAQABAADaGCDt9pPuMrVymQe5suyOZJgO6MAIwX6Jz7Tl7NchUQHclW3om5FOan+9g8rr78jskb4SB2Z+pVdjhjkaqCRJzPC6fSAAAAAAILFkUl8sWJyphiT+5+p5Rev6nLCp6DDtMQTNwLSMcOHw2hgg7faT7jK1cpkHubLsjmSYDujACMF+ic+05ezXIVHoAwAAAAAAAICEHgAAAAAAAA==";
    let transaction = Transaction::from_base64(tx_bytes_base64)?;

    let res = client.dry_run(&transaction).await?;

    if let Some(err) = res.error {
        eyre::bail!("Dry run failed: {err}");
    }

    println!("Dry run was successful!");
    // Servers since 1.33 also report the transaction and a suggested gas
    // price; older ones leave both empty.
    if let Some(version) = client.server_version() {
        println!("Server version: {version}");
    }
    println!("Suggested gas price: {:?}", res.suggested_gas_price);
    println!("Dry run result: {res:#?}");

    Ok(())
}
