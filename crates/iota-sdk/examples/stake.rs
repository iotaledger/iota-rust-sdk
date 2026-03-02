// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::{OptionExt, Result};
use iota_sdk::{graphql_client::Client, transaction_builder::TransactionBuilder, types::Address};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet();

    let my_address =
        Address::from_str("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")?;

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
