// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! This example requires running a localnet.
//! ```
//! iota start --with-faucet --with-graphql --committee-size 1 --force-regenesis
//! ```

use eyre::{Result, bail};
use iota_crypto::{IotaSigner, ed25519::Ed25519PrivateKey};
use iota_graphql_client::{Client, faucet::FaucetClient, pagination::PaginationFilter};
use iota_transaction_builder::{MovePackageData, TransactionBuilder, res};
use iota_types::{Address, Digest, Input, ObjectId, ObjectOut, StructTag};
use rand::rngs::OsRng;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse the compiled `first_package` example from the monorepo created with
    // `iota move build --dump-bytecode-as-base64`
    let data = serde_json::from_str::<MovePackageData>(SERIALIZED_FIRST_PACKAGE)?;
    let Some(compiled_package_digest) = data.digest else {
        bail!("Missing compiled package digest");
    };
    println!("Compiled Package Digest={compiled_package_digest}");

    // Create a random private key to derive a sender address and for signing
    let private_key = Ed25519PrivateKey::generate(OsRng);
    let public_key = private_key.public_key();
    let sender = public_key.derive_address();
    println!("Sender={sender}");

    // Fund the sender address for gas payment
    let faucet = FaucetClient::new_localnet();
    let Some(receipt) = faucet.request_and_wait(sender).await? else {
        bail!("Failed to request coins from faucet");
    };
    println!(
        "Balance={}",
        receipt.sent.iter().map(|coin| coin.amount).sum::<u64>()
    );

    // Get a gas coin id
    let client = Client::new_localnet();
    let gas = *client
        .coins(sender, None, PaginationFilter::default())
        .await?
        .data[0]
        .id();

    // Build the `publish` transaction
    let mut builder = TransactionBuilder::new(sender).with_client(client.clone());
    builder
        .gas_budget(50_000_000)
        .gas(gas)
        .publish(data.clone())
        .name("publish");

    // Transfer the `UpgradeCap` to the `sender`
    builder.transfer_objects(sender, [res("publish")]);

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
    let mut package_digest = None::<Digest>;
    let mut upgrade_cap_digest = None::<Digest>;

    for changed_obj in effects.as_v1().changed_objects.iter() {
        match changed_obj.output_state {
            ObjectOut::ObjectWrite { digest, owner } => {
                let object_id = changed_obj.object_id;
                let Some(obj) = client.object(object_id, None).await? else {
                    bail!("Missing object {object_id}");
                };
                if obj.as_struct().type_ == StructTag::upgrade_cap() {
                    println!("UpgradeCap={object_id}");
                    println!("Owner: {owner}");
                    upgrade_cap.replace(object_id);
                    upgrade_cap_digest.replace(digest);
                }
            }
            ObjectOut::PackageWrite { version, digest } => {
                let pkg_id = changed_obj.object_id;
                println!("PackageId={pkg_id}");
                println!("Package version: {version}");
                package_id.replace(pkg_id);
                package_digest.replace(digest);
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

    let Some(obj_ref) = client
        .object(upgrade_cap_id, None)
        .await?
        .map(|obj| obj.object_ref())
    else {
        bail!("Missing object");
    };

    // Make a `move_call` to create the `UpgradeTicket`
    let mut builder = TransactionBuilder::new(sender).with_client(client.clone());

    let upgrade_arg = builder.input(Input::ImmutableOrOwned(obj_ref));
    let policy_arg = builder.pure(255);
    let digest_arg = builder.pure(compiled_package_digest);

    // Build the `upgrade` transaction
    builder
        .gas_budget(50_000_000)
        .gas(gas)
        .move_call(Address::FRAMEWORK, "package", "authorize_upgrade")
        .arguments([upgrade_arg, policy_arg, digest_arg])
        .name("upgrade_ticket");

    builder.upgrade(package_id, res("upgrade_ticket"), data);
    let tx = builder.finish().await?;

    // Perform a dry-run to check if everything is fine
    let res = client.dry_run_tx(&tx, false).await?;
    if let Some(err) = res.error {
        bail!("Dry run failed: {err}");
    }
    let Some(effects) = res.effects else {
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
                println!("PackageId={pkg_id}");
                println!("Package version: {version}")
            }
            _ => continue,
        }
    }

    Ok(())
}

// Compiled `first_package` example
const SERIALIZED_FIRST_PACKAGE: &str = r#"{"modules":["oRzrCwYAAAAKAQAIAggUAxw+BFoGBWBBB6EBwQEI4gJACqIDGgy8A5cBDdMEBgAKAQ0BEwEUAAIMAAABCAAAAAgAAQQEAAMDAgAACAABAAAJAgMAABACAwAAEgQDAAAMBQYAAAYHAQAAEQgBAAAFCQoAAQsACwACDg8BAQwCEw8BAQgDDwwNAAoOCgYJBgEHCAQAAQYIAAEDAQYIAQQHCAEDAwcIBAEIAAQDAwUHCAQDCAAFBwgEAgMHCAQBCAIBCAMBBggEAQUBCAECCQAFBkNvbmZpZwVGb3JnZQVTd29yZAlUeENvbnRleHQDVUlEDWNyZWF0ZV9jb25maWcMY3JlYXRlX3N3b3JkAmlkBGluaXQFbWFnaWMJbXlfbW9kdWxlA25ldwluZXdfc3dvcmQGb2JqZWN0D3B1YmxpY190cmFuc2ZlcgZzZW5kZXIIc3RyZW5ndGgOc3dvcmRfdHJhbnNmZXIOc3dvcmRzX2NyZWF0ZWQIdHJhbnNmZXIKdHhfY29udGV4dAV2YWx1ZQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAgMHCAMJAxADAQICBwgDEgMCAgIHCAMVAwAAAAABCQoAEQgGAAAAAAAAAAASAQsALhELOAACAQEAAAEECwAQABQCAgEAAAEECwAQARQCAwEAAAEECwAQAhQCBAEAAAEOCgAQAhQGAQAAAAAAAAAWCwAPAhULAxEICwELAhIAAgUBAAABCAsDEQgLAAsBEgALAjgBAgYBAAABBAsACwE4AgIHAQAAAQULAREICwASAgIAAQACAQEA"],"dependencies":["0x0000000000000000000000000000000000000000000000000000000000000002","0x0000000000000000000000000000000000000000000000000000000000000001"],"digest":[246,127,102,77,186,19,68,12,161,181,56,248,210,0,91,211,245,251,165,152,0,197,250,135,171,37,177,240,133,76,122,124]}"#;
