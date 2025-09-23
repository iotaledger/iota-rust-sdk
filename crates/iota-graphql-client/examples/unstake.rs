// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use anyhow::{Context, Result};
use iota_graphql_client::{Client, query_types::ObjectFilter};
use iota_transaction_builder::{Mut, TransactionBuilder};
use iota_types::{Address, ObjectId, StructTag};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let staked_iota = client
        .objects(
            ObjectFilter {
                type_: "0x3::staking_pool::StakedIota".to_owned().into(),
                ..Default::default()
            },
            Default::default(),
        )
        .await?
        .data
        .into_iter()
        .next()
        .context("no staked iota found")?;

    // Get a valid gas coin
    let gas_coin = client
        .objects(
            ObjectFilter {
                type_: Some(StructTag::gas_coin().to_string()),
                owner: Some(*staked_iota.owner().as_address()),
                ..Default::default()
            },
            Default::default(),
        )
        .await?
        .data
        .into_iter()
        .next()
        .context("no gas coin found")?;

    let mut builder = TransactionBuilder::new(*gas_coin.owner().as_address()).with_client(client);

    builder
        .move_call(Address::THREE, "iota_system", "request_withdraw_stake")
        .params((Mut(ObjectId::from_str("0x5")?), staked_iota.object_id()))
        .gas(gas_coin.object_id())
        .gas_budget(1000000000);

    let res = builder.dry_run(false).await?;

    if let Some(err) = res.error {
        anyhow::bail!("Failed to unstake: {err}");
    }

    println!("Unstake dry run was successful!");

    Ok(())
}
