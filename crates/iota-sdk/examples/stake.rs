// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::{OptionExt, Result};
use iota_graphql_client::Client;
use iota_transaction_builder::TransactionBuilder;
use iota_types::Address;

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
        .ok_or_eyre("no validators found")?;

    println!(
        "Staking to validator {}",
        validator.name.as_deref().unwrap_or("with no name")
    );

    let mut builder = TransactionBuilder::new(my_address).with_client(client);

    builder.stake(1000000000u64, validator.address.address);

    let res = builder.dry_run(false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to stake: {err}");
    }

    println!("Stake dry run was successful!");

    Ok(())
}
