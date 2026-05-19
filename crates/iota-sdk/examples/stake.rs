// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::{OptionExt, Result};
use iota_sdk::{
    graphql_client::{Client, faucet::FaucetClient},
    transaction_builder::TransactionBuilder,
    types::Address,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();

    let my_address =
        Address::from_str("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")?;

    FaucetClient::new_localnet()
        .request_and_wait_for_finalized(my_address, &client)
        .await?;

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

    let mut builder = TransactionBuilder::new(my_address).with_client(&client);

    builder.stake(1000000000u64, validator.address.address);

    let res = builder.dry_run(false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to stake: {err}");
    }

    println!("Stake dry run was successful!");

    Ok(())
}
