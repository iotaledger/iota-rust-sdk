// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use anyhow::{Context, Result};
use iota_graphql_client::{Client, query_types::ObjectFilter};
use iota_transaction_builder::{Function, TransactionBuilder, unresolved::Input};
use iota_types::{Address, Identifier, ObjectId, StructTag};

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

    let mut builder = TransactionBuilder::new();
    let inputs = vec![
        builder.input(Input::shared(ObjectId::from_str("0x5")?, 1, true)),
        builder.input(Input::from(&staked_iota).with_owned_kind()),
    ];
    builder.move_call(
        Function::new(
            Address::THREE,
            Identifier::new("iota_system")?,
            Identifier::new("request_withdraw_stake")?,
            Default::default(),
        ),
        inputs,
    );
    builder.set_sender(*gas_coin.owner().as_address());
    builder.set_gas_budget(50000000);
    builder.set_gas_price(
        client
            .reference_gas_price(None)
            .await?
            .expect("missing ref gas price"),
    );
    builder.add_gas_objects([Input::from(&gas_coin).with_owned_kind()]);
    let txn = builder.finish()?;
    let res = client.dry_run_tx(&txn, false).await?;

    if let Some(err) = res.error {
        anyhow::bail!("Failed to unstake: {err}");
    }

    println!("Successfully unstaked!");

    Ok(())
}
