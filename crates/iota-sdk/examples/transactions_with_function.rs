// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_graphql_client::{
    Client, error::Result, pagination::PaginationFilter, query_types::TransactionsFilter,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let transactions = client
        .transactions(
            TransactionsFilter {
                function: Some("0x3::iota_system::request_add_stake".to_string()),
                ..Default::default()
            },
            PaginationFilter::default(),
        )
        .await?;

    for transaction in transactions.data() {
        println!("Digest: {}", transaction.transaction.digest());
    }

    Ok(())
}
