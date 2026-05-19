// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::{
    graphql_client::{Client, error::Result, query_types::TransactionsFilter},
    types::ObjectId,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();

    // The IOTA system state object (0x5) is a well-known shared object that is
    // present on every network including localnet.
    let shared_obj_id = ObjectId::SYSTEM_STATE;
    let transactions = client
        .transactions(
            TransactionsFilter {
                input_object: Some(shared_obj_id),
                ..Default::default()
            },
            Default::default(),
        )
        .await?;

    for transaction in transactions.data() {
        println!("Digest: {}", transaction.transaction.digest());
    }

    Ok(())
}
