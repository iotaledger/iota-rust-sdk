// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::{OptionExt, Result};
use iota_graphql_client::{Client, query_types::ObjectFilter};
use iota_transaction_builder::TransactionBuilder;
use iota_types::StructTag;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let staked_iota = client
        .objects(
            ObjectFilter {
                type_: Some(StructTag::new_staked_iota().to_string()),
                ..Default::default()
            },
            Default::default(),
        )
        .await?
        .data
        .into_iter()
        .next()
        .ok_or_eyre("no staked iota found")?;

    let mut builder =
        TransactionBuilder::new(*staked_iota.owner().as_address()).with_client(client);

    builder.unstake(staked_iota.object_id());

    let res = builder.dry_run(false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to unstake: {err}");
    }

    println!("Unstake dry run was successful!");

    Ok(())
}
