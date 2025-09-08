// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use anyhow::{Context, Result};
use iota_graphql_client::Client;
use iota_transaction_builder::{Function, TransactionBuilder, unresolved::Input};
use iota_types::{Address, Identifier, ObjectId};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let my_address =
        Address::from_str("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")?;

    let validator = client
        .active_validators(None, Default::default())
        .await?
        .data
        .into_iter()
        .next()
        .context("no validators found")?;

    let coin = client
        .object(
            ObjectId::from_str(
                "0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699",
            )?,
            None,
        )
        .await?
        .context("missing object")?;
    let gas_coin = client
        .object(
            ObjectId::from_str(
                "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab",
            )?,
            None,
        )
        .await?
        .context("missing gas coin")?;

    let mut builder = TransactionBuilder::new();
    let inputs = vec![
        builder.input(Input::shared(ObjectId::from_str("0x5")?, 1, true)),
        builder.input(Input::from(&coin).with_owned_kind()),
        builder.input(Input::pure(&validator.address.address)?),
    ];
    builder.move_call(
        Function::new(
            Address::THREE,
            Identifier::new("iota_system")?,
            Identifier::new("request_add_stake")?,
            Default::default(),
        ),
        inputs,
    );
    builder.set_sender(my_address);
    builder.set_gas_budget(50000000);
    builder.set_gas_price(
        client
            .reference_gas_price(None)
            .await?
            .context("missing ref gas price")?,
    );
    builder.add_gas_objects([Input::from(&gas_coin).with_owned_kind()]);
    let txn = builder.finish()?;
    let res = client.dry_run_tx(&txn, false).await?;

    if let Some(err) = res.error {
        anyhow::bail!("Failed to stake: {err}");
    }

    println!("Successfully staked!");

    Ok(())
}
