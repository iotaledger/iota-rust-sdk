// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use anyhow::Result;
use iota_graphql_client::{Client, pagination::PaginationFilter, query_types::TransactionsFilter};
use iota_types::ObjectId;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let shared_obj_id =
        ObjectId::from_str("0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342")?;
    let transactions = client
        .transactions(
            TransactionsFilter {
                input_object: Some(shared_obj_id),
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
