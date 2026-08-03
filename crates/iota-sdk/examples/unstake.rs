// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::{OptionExt, Result};
use iota_sdk::{
    graphql_client::{Client, query_types::ObjectFilter},
    transaction_builder::TransactionBuilder,
    types::{Address, StructTag},
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet();

    let owner: Address =
        "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151".parse()?;

    let staked_iota = client
        .objects(
            ObjectFilter {
                type_: Some(StructTag::new_staked_iota().to_string()),
                owner: Some(owner),
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

    builder.unstake(staked_iota.id());

    let res = builder.dry_run(false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to unstake: {err}");
    }

    println!("Unstake dry run was successful!");

    Ok(())
}
