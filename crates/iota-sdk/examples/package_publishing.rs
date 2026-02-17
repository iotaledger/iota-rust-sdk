// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Example: publish a Move package using TransactionBuilder.
//!
//! Build package JSON first and set it as env var:
//! `COMPILED_PACKAGE=$(iota move build --dump-bytecode-as-base64)`
//! Then run this example against localnet.

use std::env::var;

use eyre::{Result, bail};
use iota_sdk::{
    crypto::{IotaSigner, ed25519::Ed25519PrivateKey},
    graphql_client::{Client, WaitForTx, faucet::FaucetClient},
    transaction_builder::{TransactionBuilder, assigned},
    types::{Address, MovePackageData},
};
use rand::rngs::OsRng;

#[tokio::main]
async fn main() -> Result<()> {
    let package_data_json =
        var("COMPILED_PACKAGE").map_err(|_| eyre::eyre!("COMPILED_PACKAGE env var is required"))?;
    let package_data = serde_json::from_str::<MovePackageData>(&package_data_json)?;

    let private_key = Ed25519PrivateKey::generate(OsRng);
    let sender = private_key.public_key().derive_address();

    let client = Client::new_localnet();
    let faucet = FaucetClient::new_localnet();
    if faucet
        .request_and_wait_for_finalized(sender, &client)
        .await?
        .is_none()
    {
        bail!("Failed to request coins from faucet");
    }

    let mut builder = TransactionBuilder::new(sender).with_client(client.clone());
    builder
        .publish(package_data)
        .assign("upgrade_cap")
        .transfer_objects(Address::from(sender), [assigned("upgrade_cap")]);

    let tx = builder.finish().await?;

    let dry_run = client.dry_run_tx(&tx, false).await?;
    if let Some(err) = dry_run.error {
        bail!("Dry run failed: {err}");
    }
    println!("Publish dry run succeeded");

    let sig = private_key.sign_transaction(&tx)?;
    let effects = client.execute_tx(&[sig], &tx, WaitForTx::Finalized).await?;
    println!("Publish status: {:?}", effects.status());

    Ok(())
}
