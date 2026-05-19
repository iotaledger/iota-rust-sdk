// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::graphql_client::{
    Client, error::Result, pagination::PaginationFilter, query_types::TransactionsFilter,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();

    let latest = client
        .transactions(TransactionsFilter::default(), PaginationFilter::default())
        .await?
        .data
        .into_iter()
        .next()
        .expect("no transactions available on the network");
    let digest = latest.transaction.digest();
    println!("Querying transaction: {digest}");

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
