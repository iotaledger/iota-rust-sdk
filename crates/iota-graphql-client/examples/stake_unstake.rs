// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use anyhow::{Context, Result};
use base64ct::Encoding;
use iota_graphql_client::{Client, query_types::ObjectFilter};
use iota_transaction_builder::{
    Function, TransactionBuilder,
    unresolved::{Input, InputKind, Value},
};
use iota_types::{Address, Identifier, ObjectId, StructTag};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let my_address =
        Address::from_str("0xda06e01d11c8d3ef8f8e238c2f144076fdc6832378fb48b153d57027ae868b39")?;

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
                "0xcef41d45f4b1da269d95094097ef523f34ce987465fc0f559765decfe351fb61",
            )?,
            None,
        )
        .await?
        .context("missing object")?;
    let gas_coin = client
        .object(
            ObjectId::from_str(
                "0x8e6a474ae81616e0ec4e2844d2cd3f21bc42cb0f87bf5c39745ed13a8dabe2d7",
            )?,
            None,
        )
        .await?
        .context("missing gas coin")?;

    let mut builder = TransactionBuilder::new();
    let inputs = vec![
        builder.input(Input::shared(ObjectId::from_str("0x5")?, 1, true)),
        builder.input(Input::from(&coin).with_owned_kind()),
        builder.input(Input {
            kind: Some(InputKind::Pure),
            value: Some(Value::String(base64ct::Base64::encode_string(
                validator.address.address.as_bytes(),
            ))),
            ..Default::default()
        }),
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
        anyhow::bail!("Failed to stake iota: {err}");
    }

    // Find a random StakedIota to demonstrate unstaking
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
        anyhow::bail!("Failed to unstake iota: {err}");
    }

    Ok(())
}
