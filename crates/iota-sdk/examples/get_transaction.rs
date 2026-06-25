// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::{
    graphql_client::{Client, error::Result},
    types::TransactionDigest,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet();
    let digest = TransactionDigest::from_base58("FczF9bnUpcizyZscYV2djwSqKMWaKngiGA5bUdGjAroj")?;

    let signed_transaction = client.transaction(digest).await?.expect("tx not found");
    println!("Signed Transaction: {signed_transaction:#?}\n");

    let transaction_effects = client
        .transaction_effects(digest)
        .await?
        .expect("tx not found");
    println!("Transaction Effects: {transaction_effects:#?}\n");

    let transaction_data_effects = client
        .transaction_data_effects(digest)
        .await?
        .expect("tx not found");
    println!("Transaction Data Effects: {transaction_data_effects:#?}");

    Ok(())
}
