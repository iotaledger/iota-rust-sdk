// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::graphql_client::{Client, error::GraphQLResult, pagination::PaginationFilter};

#[tokio::main]
async fn main() -> GraphQLResult<()> {
    let client = Client::new_localnet();

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
