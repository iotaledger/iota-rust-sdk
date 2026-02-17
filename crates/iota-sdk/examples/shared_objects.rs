// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Example: working with shared objects.
//!
//! Demonstrates:
//! 1) read a shared object and verify ownership type
//! 2) query transactions that referenced that shared object as input
//!
//! Set SHARED_OBJECT_ID to inspect a specific shared object.

use std::{env::var, str::FromStr};

use eyre::{OptionExt, Result, bail};
use iota_sdk::{
    graphql_client::{Client, query_types::TransactionsFilter},
    types::ObjectId,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let shared_object_id = ObjectId::from_str(
        &var("SHARED_OBJECT_ID").map_err(|_| eyre::eyre!("SHARED_OBJECT_ID env var is required"))?,
    )?;

    let obj = client
        .object(shared_object_id, None)
        .await?
        .ok_or_eyre("shared object not found")?;

    match obj.owner() {
        iota_types::Owner::Shared(v) => {
            println!("Object is shared. initial_shared_version={v}");
        }
        other => {
            bail!("Object is not shared: {other:?}");
        }
    }

    let txs = client
        .transactions(
            TransactionsFilter {
                input_object: Some(shared_object_id),
                ..Default::default()
            },
            Default::default(),
        )
        .await?;

    println!("Transactions touching shared object: {}", txs.data().len());
    for tx in txs.data().iter().take(10) {
        println!("- {}", tx.transaction.digest());
    }

    Ok(())
}
