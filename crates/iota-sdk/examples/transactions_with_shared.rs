// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use iota_sdk::{
    graphql_client::{Client, error::Result, query_types::TransactionBlockFilter},
    types::ObjectId,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet();

    let shared_obj_id =
        ObjectId::from_str("0x7cab491740d51e0d75b26bf9984e49ba2e32a2d0694cabcee605543ed13c7dec")?;
    let transactions = client
        .transactions(
            TransactionBlockFilter::default().with_input_object(shared_obj_id),
            Default::default(),
        )
        .await?;

    for transaction in transactions.data() {
        println!("Digest: {}", transaction.transaction.digest());
    }

    Ok(())
}
