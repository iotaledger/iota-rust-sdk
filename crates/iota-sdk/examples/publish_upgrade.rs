// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! This example requires you to compile a Move package first.
//!
//! ```bash
//! cd /path/to/your/move/package/Move.toml
//!
//! export COMPILED_PACKAGE=$(iota move build --dump-bytecode-as-base64)
//! ```
//!
//! ```fish
//! cd /path/to/your/move/package/Move.toml
//!
//! set -x COMPILED_PACKAGE (iota move build --dump-bytecode-as-base64)
//! ```

use std::env::var;

use eyre::{Result, bail};
use iota_crypto::{IotaSigner, ed25519::Ed25519PrivateKey};
use iota_graphql_client::{Client, faucet::FaucetClient};
use iota_transaction_builder::{MovePackageData, TransactionBuilder, builder::UpgradePolicy, res};
use iota_types::{Address, ObjectId, ObjectOut, StructTag};
use rand::rngs::OsRng;

#[tokio::main]
async fn main() -> Result<()> {
    let compiled_package = var("COMPILED_PACKAGE")?;

    // Parse the compiled `first_package` example from the monorepo created with
    // `iota move build --dump-bytecode-as-base64`
    let data = serde_json::from_str::<MovePackageData>(&compiled_package)?;
    let Some(compiled_package_digest) = data.digest else {
        bail!("Missing compiled package digest");
    };
    println!("Compiled Package Digest: {compiled_package_digest}");

    // Create a random private key to derive a sender address and for signing
    let private_key = Ed25519PrivateKey::generate(OsRng);
    let sender = private_key.public_key().derive_address();
    println!("Sender: {sender}");

    // Fund the sender address for gas payment
    let faucet = FaucetClient::new_devnet();
    let Some(receipt) = faucet.request_and_wait(sender).await? else {
        bail!("Failed to request coins from faucet");
    };
    println!(
        "Available Balance: {}",
        receipt.sent.iter().map(|coin| coin.amount).sum::<u64>()
    );

    let client = Client::new_devnet();

    // Build the `publish` PTB, that consists of 2 steps;
    // 1. Publish the package and receive the upgrade cap in return
    // 2. Transfer the upgrade cap to the sender address
    let mut builder = TransactionBuilder::new(sender).with_client(client.clone());
    builder
        .publish(data.clone())
        .name("upgrade_cap")
        .transfer_objects(sender, [res("upgrade_cap")]);

    let tx = builder.finish().await?;

    // Perform a dry-run first
    let result = client.dry_run_tx(&tx, false).await?;
    if let Some(err) = result.error {
        bail!("Dry run failed: {err}");
    }
    let Some(effects) = result.effects else {
        bail!("Dry run failed: no effects");
    };
    println!("Effects status (dry run): {:?}", effects.status());

    // Sign and execute the transaction (publish the package)
    println!("Publishing package");
    let sig = private_key.sign_transaction(&tx)?;
    let Some(effects) = client.execute_tx(&[sig], &tx).await? else {
        bail!("Transaction failed: no effects");
    };
    println!("Effects status (publish): {:?}", effects.status());

    // Wait some time for the indexer to process the tx
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Resolve UpgradeCap and PackageId via the client
    let mut upgrade_cap = None::<ObjectId>;
    let mut package_id = None::<ObjectId>;
    for changed_obj in effects.as_v1().changed_objects.iter() {
        match changed_obj.output_state {
            ObjectOut::ObjectWrite { owner, .. } => {
                let object_id = changed_obj.object_id;
                let Some(obj) = client.object(object_id, None).await? else {
                    bail!("Missing object {object_id}");
                };
                if obj.as_struct().type_ == StructTag::upgrade_cap() {
                    println!("UpgradeCap: {object_id}");
                    println!("UpgradeCapOwner: {}", owner.into_address());
                    upgrade_cap.replace(object_id);
                }
            }
            ObjectOut::PackageWrite { version, .. } => {
                let pkg_id = changed_obj.object_id;
                println!("PackageId: {pkg_id}");
                println!("Package version: {version}");
                package_id.replace(pkg_id);
            }
            _ => continue,
        }
    }

    let Some(upgrade_cap_id) = upgrade_cap else {
        bail!("Missing upgrade cap");
    };
    let Some(package_id) = package_id else {
        bail!("Missing package id");
    };

    // Build the `upgrade` PTB, that consists of 3 steps
    // 1. Create the upgrade ticket
    // 2. Get the upgrade receipt
    // 3. Finalize the upgrade
    let mut builder = TransactionBuilder::new(sender).with_client(client.clone());
    builder
        .move_call(Address::FRAMEWORK, "package", "authorize_upgrade")
        .arguments((
            upgrade_cap_id,
            UpgradePolicy::Compatible as u8,
            compiled_package_digest,
        ))
        .name("upgrade_ticket")
        .upgrade(package_id, res("upgrade_ticket"), data)
        .name("upgrade_receipt")
        .move_call(Address::FRAMEWORK, "package", "commit_upgrade")
        .arguments((upgrade_cap_id, res("upgrade_receipt")));

    // Finalize the PTB
    let tx = builder.finish().await?;

    // Perform a dry-run to check if everything is fine
    let result = client.dry_run_tx(&tx, false).await?;
    if let Some(err) = result.error {
        bail!("Dry run failed: {err}");
    }
    let Some(effects) = result.effects else {
        bail!("Dry run failed: no effects");
    };
    println!("Effects status (dry run): {:?}", effects.status());

    // Sign and execute the transaction (upgrade the package)
    println!("Upgrading package");
    let sig = private_key.sign_transaction(&tx)?;
    let Some(effects) = client.execute_tx(&[sig], &tx).await? else {
        bail!("Transaction failed: no effects");
    };
    println!("Effects status (upgrade): {:?}", effects.status());

    // Wait some time for the indexer to process the tx
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Print the new package version (should now be 2)
    for changed_obj in effects.as_v1().changed_objects.iter() {
        match changed_obj.output_state {
            ObjectOut::PackageWrite { version, .. } => {
                let pkg_id = changed_obj.object_id;
                println!("PackageId: {pkg_id}");
                println!("Package version: {version}")
            }
            _ => continue,
        }
    }

    Ok(())
}
