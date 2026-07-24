// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::graphql_client::{Client, error::Result, pagination::PaginationFilter};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();

    // Fetch a recent transaction from the network so the example does not
    // depend on a specific digest that may have been pruned.
    let transactions = client
        .transactions(None, PaginationFilter::default())
        .await?;
    let digest = transactions
        .data()
        .first()
        .expect("no transactions found")
        .transaction
        .digest();

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
