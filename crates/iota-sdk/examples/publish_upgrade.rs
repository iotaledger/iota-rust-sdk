// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! This example allows you to publish any Move package by compiling it
//! first using the `iota` binary. For demonstration purposes this example
//! immediately upgrades the package after publishing it.
//!
//! ```bash
//! cd /path/to/your/move/package
//! export COMPILED_PACKAGE=$(iota move build --dump-bytecode-as-base64)
//! ```
//!
//! ```fish
//! cd /path/to/your/move/package
//! set -x COMPILED_PACKAGE (iota move build --dump-bytecode-as-base64)
//! ```
//!
//! With this example it is necessary to run a localnet:
//!
//! ```sh
//! iota start --with-faucet --with-graphql --committee-size 1 --force-regenesis
//! ```

use std::env::var;

use eyre::{Result, bail};
use iota_crypto::{IotaSigner, ed25519::Ed25519PrivateKey};
use iota_graphql_client::{Client, WaitForTx, faucet::FaucetClient};
use iota_transaction_builder::{TransactionBuilder, res};
use iota_types::{Address, MovePackageData, ObjectId, ObjectOut, StructTag, UpgradePolicy};
use rand::rngs::OsRng;

#[tokio::main]
async fn main() -> Result<()> {
    // Read and parse the compiled package
    let package_data_json = if let Ok(compiled_package) = var("COMPILED_PACKAGE") {
        println!("Using custom Move package found in env var.");
        compiled_package
    } else {
        println!("No compiled package found in env var. Using default.");
        PRECOMPILED_PACKAGE.to_string()
    };
    let package_data = serde_json::from_str::<MovePackageData>(&package_data_json)?;
    println!("Modules: {}", package_data.modules.len());
    println!("Dependencies: {}", package_data.dependencies.len());
    println!("Digest: {}", package_data.digest);

    // Create a random private key to derive a sender address and for signing
    let private_key = Ed25519PrivateKey::generate(OsRng);
    let sender = private_key.public_key().derive_address();
    println!("Sender: {sender}");

    // Fund the sender address for gas payment
    let faucet = FaucetClient::new_localnet();
    if faucet.request_and_wait(sender).await?.is_none() {
        bail!("Failed to request coins from faucet");
    };

    let client = Client::new_localnet();

    // Build the `publish` PTB
    let mut builder = TransactionBuilder::new(sender).with_client(client.clone());
    builder
        // Publish the package and receive the upgrade cap
        .publish(package_data.clone())
        .name("upgrade_cap")
        // Transfer the upgrade cap to the sender address
        .transfer_objects(sender, [res("upgrade_cap")]);

    let tx = builder.finish().await?;

    // Perform a dry-run first to check if everything is correct
    println!("> Publishing package (dry run):");
    let result = client.dry_run_tx(&tx, false).await?;
    if let Some(err) = result.error {
        bail!("Dry run failed: {err}");
    }
    let Some(effects) = result.effects else {
        bail!("Dry run failed: no effects");
    };
    println!("{:?}", effects.status());

    // Sign and execute the transaction (publish the package)
    println!("> Publishing package:");
    let sig = private_key.sign_transaction(&tx)?;
    let effects = client.execute_tx(&[sig], &tx, WaitForTx::Finalized).await?;
    println!("{:?}", effects.status());

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
                if obj.as_struct().type_ == StructTag::new_upgrade_cap() {
                    println!("UpgradeCap: {object_id}");
                    println!("UpgradeCapOwner: {}", owner.into_address());
                    upgrade_cap.replace(object_id);
                }
            }
            ObjectOut::PackageWrite { version, .. } => {
                let pkg_id = changed_obj.object_id;
                println!("Package ID: {pkg_id}");
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

    // Build the `upgrade` PTB
    let mut builder = TransactionBuilder::new(sender).with_client(client.clone());
    builder
        // Authorize the upgrade by providing the upgrade cap object id to receive an upgrade
        // ticket
        .move_call(Address::FRAMEWORK, "package", "authorize_upgrade")
        .arguments((
            upgrade_cap_id,
            UpgradePolicy::Compatible as u8,
            package_data.digest,
        ))
        .name("upgrade_ticket")
        // Upgrade the package to receive an upgrade receipt
        .upgrade(package_id, package_data, res("upgrade_ticket"))
        .name("upgrade_receipt")
        // Commit the upgrade using the receipt
        .move_call(Address::FRAMEWORK, "package", "commit_upgrade")
        .arguments((upgrade_cap_id, res("upgrade_receipt")));

    let tx = builder.finish().await?;

    // Perform a dry-run first to check if everything is correct
    println!("> Upgrading package (dry run):");
    let result = client.dry_run_tx(&tx, false).await?;
    if let Some(err) = result.error {
        bail!("Dry run failed: {err}");
    }
    let Some(effects) = result.effects else {
        bail!("Dry run failed: no effects");
    };
    println!("{:?}", effects.status());

    // Sign and execute the transaction (upgrade the package)
    println!("> Upgrading package:");
    let sig = private_key.sign_transaction(&tx)?;
    let effects = client.execute_tx(&[sig], &tx, None).await?;
    println!("{:?}", effects.status());

    // Wait some time for the indexer to process the tx
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Print the new package version (should now be 2)
    for changed_obj in effects.as_v1().changed_objects.iter() {
        match changed_obj.output_state {
            ObjectOut::PackageWrite { version, .. } => {
                let pkg_id = changed_obj.object_id;
                println!("New Package ID: {pkg_id}");
                println!("New Package version: {version}")
            }
            _ => continue,
        }
    }

    Ok(())
}

// Pre-compiled `first_package` example
const PRECOMPILED_PACKAGE: &str = r#"{"modules":["oRzrCwYAAAAKAQAIAggUAxw+BFoGBWBBB6EBwQEI4gJACqIDGgy8A5cBDdMEBgAKAQ0BEwEUAAIMAAABCAAAAAgAAQQEAAMDAgAACAABAAAJAgMAABACAwAAEgQDAAAMBQYAAAYHAQAAEQgBAAAFCQoAAQsACwACDg8BAQwCEw8BAQgDDwwNAAoOCgYJBgEHCAQAAQYIAAEDAQYIAQQHCAEDAwcIBAEIAAQDAwUHCAQDCAAFBwgEAgMHCAQBCAIBCAMBBggEAQUBCAECCQAFBkNvbmZpZwVGb3JnZQVTd29yZAlUeENvbnRleHQDVUlEDWNyZWF0ZV9jb25maWcMY3JlYXRlX3N3b3JkAmlkBGluaXQFbWFnaWMJbXlfbW9kdWxlA25ldwluZXdfc3dvcmQGb2JqZWN0D3B1YmxpY190cmFuc2ZlcgZzZW5kZXIIc3RyZW5ndGgOc3dvcmRfdHJhbnNmZXIOc3dvcmRzX2NyZWF0ZWQIdHJhbnNmZXIKdHhfY29udGV4dAV2YWx1ZQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAgMHCAMJAxADAQICBwgDEgMCAgIHCAMVAwAAAAABCQoAEQgGAAAAAAAAAAASAQsALhELOAACAQEAAAEECwAQABQCAgEAAAEECwAQARQCAwEAAAEECwAQAhQCBAEAAAEOCgAQAhQGAQAAAAAAAAAWCwAPAhULAxEICwELAhIAAgUBAAABCAsDEQgLAAsBEgALAjgBAgYBAAABBAsACwE4AgIHAQAAAQULAREICwASAgIAAQACAQEA"],"dependencies":["0x0000000000000000000000000000000000000000000000000000000000000002","0x0000000000000000000000000000000000000000000000000000000000000001"],"digest":[246,127,102,77,186,19,68,12,161,181,56,248,210,0,91,211,245,251,165,152,0,197,250,135,171,37,177,240,133,76,122,124]}"#;
