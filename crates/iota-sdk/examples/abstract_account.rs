// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::{OptionExt, Result, bail};
use iota_sdk::{
    crypto::ed25519::Ed25519PrivateKey,
    graphql_client::{Client, WaitForTx, faucet::FaucetClient},
    transaction_builder::{
        MoveAuthenticatorBuilder, Shared, SharedMut, TransactionBuilder, assigned,
    },
    types::{Address, Identifier, MovePackageData, ObjectId, ObjectOut},
};
use rand::rngs::OsRng;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();
    let account_address = Address::from(setup_account(&client).await?);
    let to_address =
        Address::from_str("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;

    // Fund the sender address for gas payment
    if FaucetClient::new_localnet()
        .request_and_wait_for_finalized(account_address, &client)
        .await?
        .is_none()
    {
        bail!("Failed to request coins from faucet");
    };

    let mut builder = TransactionBuilder::new(account_address).with_client(&client);
    builder.send_iota(to_address, 5000000000u64);

    let move_authenticator = MoveAuthenticatorBuilder::new(account_address.into())
        .call_args(("hello", Shared(ObjectId::CLOCK)))
        .finish(&client)
        .await?;

    let effects = builder
        .execute(&move_authenticator, WaitForTx::Finalized)
        .await?;
    println!(
        "Sending IOTA via abstract account: {:?}",
        effects.as_v1().status
    );

    Ok(())
}

async fn setup_account(client: &Client) -> Result<ObjectId> {
    // Parse the precompiled move package
    let package_data = serde_json::from_str::<MovePackageData>(PRECOMPILED_PACKAGE)?;

    // Create a random private key to derive a sender address
    let private_key = Ed25519PrivateKey::generate(OsRng);
    let sender = private_key.public_key().derive_address();

    // Fund the sender address for gas payment
    if FaucetClient::new_localnet()
        .request_and_wait_for_finalized(sender, client)
        .await?
        .is_none()
    {
        bail!("Failed to request coins from faucet");
    };

    // Build the `publish` PTB
    let mut builder = TransactionBuilder::new(sender).with_client(&client);
    builder
        // Publish the package and receive the upgrade cap
        .publish_package(package_data)
        .assign("upgrade_cap")
        // Transfer the upgrade cap to the sender address
        .transfer_objects(sender, [assigned("upgrade_cap")]);

    // Sign and execute the transaction (publish the package)
    let effects = builder.execute(&private_key, WaitForTx::Finalized).await?;
    println!("Publishing package: {:?}\n", effects.as_v1().status);

    // Get package, package metadata and account IDs from the effects
    let mut package_id = None::<ObjectId>;
    let mut package_metadata_id = None::<ObjectId>;
    let mut account_id = None::<ObjectId>;

    for changed_obj in effects.as_v1().changed_objects.iter() {
        match changed_obj.output_state {
            ObjectOut::PackageWrite { .. } => {
                package_id.replace(changed_obj.object_id);
            }
            ObjectOut::ObjectWrite { .. } => {
                let object_id = changed_obj.object_id;
                let object = client.object(object_id, None).await?;

                if let Some(object) = object {
                    if object.as_struct().object_type().name()
                        == &Identifier::from_static("PackageMetadataV1")
                    {
                        package_metadata_id.replace(object_id);
                    }
                    if object.as_struct().object_type().name()
                        == &Identifier::from_static("Account")
                    {
                        account_id.replace(object_id);
                    }
                }
            }
            _ => continue,
        }
    }

    let package_id = package_id.ok_or_eyre("Missing package id")?;
    let package_metadata_id = package_metadata_id.ok_or_eyre("Missing package metadata id")?;
    let account_id = account_id.ok_or_eyre("Missing account id")?;

    println!("Package ID: {package_id}");
    println!("PackageMetadataV1 ID: {package_metadata_id}");
    println!("Account ID: {account_id}\n");

    // Build the `link_auth` PTB
    let mut builder = TransactionBuilder::new(sender).with_client(&client);
    builder
        .move_call(package_id, "account", "link_auth")
        .arguments((
            SharedMut(account_id),
            package_metadata_id,
            "account",
            "authenticate",
        ));

    // Sign and execute the transaction (link the authenticator)
    let effects = builder.execute(&private_key, WaitForTx::Finalized).await?;
    println!(
        "Linking account to authenticate method: {:?}\n",
        effects.as_v1().status
    );

    Ok(account_id)
}

/// The package below, compiled and exported using `iota move build
/// --dump-bytecode-as-base64``
const PRECOMPILED_PACKAGE: &str = r#"{"modules":["oRzrCwYAAAALAQAUAhQmAzorBGUGBWtPB7oBwAII+gNgBtoECRDjBCoKjQULDJgFQgAJAgkCCwINAg4CFgIXAhoCGwEKAAEMAAAAAgACAgIAAwMHAQgBBAQIAAUIBAAGBQgACAcCAAkGBwAAEwABAAAUAgEAAAwDAQABDwsBAQgDEAkKAQgFFQQFAAcYBwEBDAkZDA0ABgYEBgMGAggBBwgHAAQIAAYIBggICAgFBggACAgGCAQGCAIGCAcBBwgHAQgFAQgAAQkAAQsDAQgAAwYIBggICAgBCwMBCQACCQALAwEJAAEKAgEICAdBQ0NPVU5UB0FjY291bnQLQXV0aENvbnRleHQaQXV0aGVudGljYXRvckZ1bmN0aW9uUmVmVjEFQ2xvY2sRUGFja2FnZU1ldGFkYXRhVjEGU3RyaW5nCVR4Q29udGV4dANVSUQHYWNjb3VudAVhc2NpaQxhdXRoX2NvbnRleHQMYXV0aGVudGljYXRlFmF1dGhlbnRpY2F0b3JfZnVuY3Rpb24FY2xvY2sRY3JlYXRlX2FjY291bnRfdjEbY3JlYXRlX2F1dGhfZnVuY3Rpb25fcmVmX3YxC2R1bW15X2ZpZWxkAmlkBGluaXQJbGlua19hdXRoA25ldwZvYmplY3QQcGFja2FnZV9tZXRhZGF0YRNwdWJsaWNfc2hhcmVfb2JqZWN0BnN0cmluZwh0cmFuc2Zlcgp0eF9jb250ZXh0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACCgIGBWhlbGxvDmlvdGE6Om1ldGFkYXRhGgEAAAAAAAAAEQEMYXV0aGVudGljYXRlAQABAAIBEggFAQIBEQEAAAAAAQULAREFEgA4AAIBAQAACAkLAQsCCwM4AQwECwALBDgCAgIBAAABCQsBBwARByEEBgUIBgAAAAAAAAAAJwIA"],"dependencies":["0x0000000000000000000000000000000000000000000000000000000000000002","0x0000000000000000000000000000000000000000000000000000000000000001"],"digest":[236,68,86,252,91,28,224,206,146,112,120,93,47,52,14,168,169,132,252,75,45,104,10,116,171,91,155,100,66,111,66,147]}"#;

#[expect(unused)]
const PACKAGE: &str = r#"
module account::account;

use iota::package_metadata::PackageMetadataV1;
use iota::account;
use iota::authenticator_function;

public struct Account has key, store {
    id: UID,
}

public struct ACCOUNT has drop {}

fun init(_otw: ACCOUNT, ctx: &mut TxContext) {
    // Shares the account object, anyone can claim it by calling the link_auth function
    transfer::public_share_object(Account {
        id: object::new(ctx),
    });
}

public fun link_auth(account: Account, package: &PackageMetadataV1, module_name: std::ascii::String, function_name: std::ascii::String) {
    let authenticator = authenticator_function::create_auth_function_ref_v1<Account>(package, module_name, function_name);
    account::create_account_v1<Account>(account, authenticator);
}

/// An unsecure example authenticator function that checks if the provided message is "hello".
#[authenticator]
public fun authenticate(
    _account: &Account,
    msg: std::ascii::String,
    _clock: &iota::clock::Clock,
    _auth_ctx: &iota::auth_context::AuthContext,
    _ctx: &TxContext,
) {
    assert!(msg == std::ascii::string(b"hello"), 0);
}
"#;
