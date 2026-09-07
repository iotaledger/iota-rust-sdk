// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::{OptionExt, Result};
use iota_sdk::{
    crypto::{IotaSigner, ed25519::Ed25519PrivateKey},
    graphql_client::{Client, faucet::FaucetClient},
    transaction_builder::WaitForTransaction,
    types::{IdOperation, ObjectOut},
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

    println!(
        "Staking to validator {}",
        validator.name.as_deref().unwrap_or("with no name")
    );

    let mut builder = client.transaction_builder(owner);
    builder.stake(1_000_000_000u64, validator.address.address);
    let stake_tx = builder.finish().await?;
    let sig = private_key.sign_transaction(&stake_tx)?;
    let effects = client
        .execute_transaction(&[sig], &stake_tx, WaitForTransaction::Finalized)
        .await?;

    // The stake is in the effects, so no query is needed to find it.
    let staked_iota = effects
        .as_v1()
        .changed_objects
        .iter()
        .find(|obj| {
            obj.id_operation == IdOperation::Created
                && matches!(obj.output_state, ObjectOut::ObjectWrite { owner: o, .. } if o.into_address() == owner)
        })
        .ok_or_eyre("stake transaction created no stake")?
        .object_id;

    let mut builder = client.transaction_builder(owner);

    builder.unstake(staked_iota);

    let res = builder.dry_run(false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to unstake: {err}");
    }

    println!("Unstake dry run was successful!");

    Ok(())
}
