// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::{OptionExt, Result};
use iota_sdk::{
    crypto::{IotaSigner, ed25519::Ed25519PrivateKey},
    graphql_client::{Client, faucet::FaucetClient, query_types::ObjectFilter},
    transaction_builder::WaitForTransaction,
    types::StructTag,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();

    let private_key = Ed25519PrivateKey::new([9; Ed25519PrivateKey::LENGTH]);
    let owner = private_key.public_key().derive_address();

    FaucetClient::new_localnet()
        .request_and_wait_for_finalized(owner, &client)
        .await?;

    // A fresh localnet has nothing staked, so stake first and unstake that.
    let validator = client
        .active_validators(None, Default::default())
        .await?
        .data
        .into_iter()
        .next()
        .ok_or_eyre("no validators found")?;

    let mut builder = client.transaction_builder(owner);
    builder.stake(1_000_000_000u64, validator.address.address);
    let stake_tx = builder.finish().await?;
    let sig = private_key.sign_transaction(&stake_tx)?;
    // Wait for finalization: the stake is not queryable until the indexer,
    // which trails execution, has caught up.
    client
        .execute_transaction(&[sig], &stake_tx, WaitForTransaction::Finalized)
        .await?;

    let staked_iota = client
        .objects(
            ObjectFilter::default()
                .with_type(StructTag::new_staked_iota().to_string())
                .with_owner(owner),
            Default::default(),
        )
        .await?
        .data
        .into_iter()
        .next()
        .ok_or_eyre("no staked iota found")?;

    let mut builder = client.transaction_builder(*staked_iota.owner().as_address());

    builder.unstake(staked_iota.id());

    let res = builder.dry_run(false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to unstake: {err}");
    }

    println!("Unstake dry run was successful!");

    Ok(())
}
