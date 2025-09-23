// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use anyhow::{Context, Result};
use iota_graphql_client::Client;
use iota_transaction_builder::{Mut, TransactionBuilder};
use iota_types::{Address, ObjectId};

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

    println!(
        "Staking to validator {}",
        validator.name.as_deref().unwrap_or("with no name")
    );

    let mut builder = TransactionBuilder::new(my_address).with_client(client);

    builder
        .move_call(Address::THREE, "iota_system", "request_add_stake")
        .params((
            Mut(ObjectId::from_str("0x5")?),
            ObjectId::from_str(
                "0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699",
            )?,
            &validator.address.address,
        ))
        .gas(ObjectId::from_str(
            "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab",
        )?)
        .gas_budget(1000000000);

    let res = builder.dry_run(false).await?;

    if let Some(err) = res.error {
        anyhow::bail!("Failed to stake: {err}");
    }

    println!("Stake dry run was successful!");

    Ok(())
}
