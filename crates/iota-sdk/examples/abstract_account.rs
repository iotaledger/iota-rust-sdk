// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::{OptionExt, Result, bail};
use iota_sdk::{
    crypto::ed25519::Ed25519PrivateKey,
    graphql_client::{Client, WaitForTx, faucet::FaucetClient},
    transaction_builder::{MoveAuthenticatorBuilder, Shared, SharedMut, TransactionBuilder, res},
    types::{Address, IdentifierRef, MovePackageData, ObjectId, ObjectOut},
};
use rand::rngs::OsRng;

#[tokio::main]
async fn main() -> Result<()> {
    let from_address = Address::from(setup_account().await?);
    let to_address =
        Address::from_str("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;

    // Fund the sender address for gas payment
    if FaucetClient::new_localnet()
        .request_and_wait(from_address)
        .await?
        .is_none()
    {
        bail!("Failed to request coins from faucet");
    };

    let client = Client::new_localnet();

    let mut builder = TransactionBuilder::new(from_address).with_client(&client);
    builder.send_iota(to_address, 5000000000u64);

    let move_authenticator = MoveAuthenticatorBuilder::new(from_address.into())
        .call_args(("hello", Shared(ObjectId::CLOCK)))
        .finish(&client)
        .await?;

    let effects = builder
        .execute(&move_authenticator, WaitForTx::Finalized)
        .await?;

    println!("Sending IOTA via abstract account: {:?}", effects.status());

    Ok(())
}

async fn setup_account() -> Result<ObjectId> {
    // Parse the precompiled move package
    let package_data = serde_json::from_str::<MovePackageData>(PRECOMPILED_PACKAGE)?;

    // Create a random private key to derive a sender address
    let private_key = Ed25519PrivateKey::generate(OsRng);
    let sender = private_key.public_key().derive_address();

    // Fund the sender address for gas payment
    if FaucetClient::new_localnet()
        .request_and_wait(sender)
        .await?
        .is_none()
    {
        bail!("Failed to request coins from faucet");
    };

    let client = Client::new_localnet();

    // Build the `publish` PTB
    let mut builder = TransactionBuilder::new(sender).with_client(&client);
    builder
        // Publish the package and receive the upgrade cap
        .publish(package_data)
        .name("upgrade_cap")
        // Transfer the upgrade cap to the sender address
        .transfer_objects(sender, [res("upgrade_cap")]);

    // Sign and execute the transaction (publish the package)
    let effects = builder.execute(&private_key, WaitForTx::Finalized).await?;

    println!("Publishing package: {:?}\n", effects.status());

    // Wait some time for the indexer to process the tx
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

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
                    if object.as_struct().type_.name
                        == *IdentifierRef::const_new("PackageMetadataV1")
                    {
                        package_metadata_id.replace(object_id);
                    }
                    if object.as_struct().type_.name == *IdentifierRef::const_new("Account") {
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
        effects.status()
    );

    Ok(account_id)
}

/// The package below, compiled and exported using --dump-bytecode-as-base64
const PRECOMPILED_PACKAGE: &str = r#"{"modules":["oRzrCwYAAAALAQASAhImAzgrBGMGBWlPB7gBmgII0gNgBrIECRC7BCoK5QQLDPAEQgAJAgkCCwINAhUCFgIZAhoBCgABDAAAAAIAAQMHAQgBAgICAAMECAAECAQABQUIAAcHAgAIBgcAABIAAQAAEwIBAAAMAwEAAQ4LAQEIAQ8JCgEIBBQEBQAGFwcBAQwIGAwNAAYGBAYDBgIIAQcIBwAECAAGCAYICAgIBQYIAAgIBggEBggDBggHAQcIBwEIBQEIAAEJAAELAgEIAAMGCAYICAgIAQsCAQkAAgkACwIBCQABCgIBCAgHQUNDT1VOVAdBY2NvdW50C0F1dGhDb250ZXh0E0F1dGhlbnRpY2F0b3JJbmZvVjEFQ2xvY2sRUGFja2FnZU1ldGFkYXRhVjEGU3RyaW5nCVR4Q29udGV4dANVSUQHYWNjb3VudAVhc2NpaQxhdXRoX2NvbnRleHQMYXV0aGVudGljYXRlBWNsb2NrEWNyZWF0ZV9hY2NvdW50X3YxE2NyZWF0ZV9hdXRoX2luZm9fdjELZHVtbXlfZmllbGQCaWQEaW5pdAlsaW5rX2F1dGgDbmV3Bm9iamVjdBBwYWNrYWdlX21ldGFkYXRhE3B1YmxpY19zaGFyZV9vYmplY3QGc3RyaW5nCHRyYW5zZmVyCnR4X2NvbnRleHQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIKAgYFaGVsbG8OaW90YTo6bWV0YWRhdGEaAQAAAAAAAAARAQxhdXRoZW50aWNhdGUBAAEAAgERCAUBAgEQAQAAAAABBQsBEQUSADgAAgEBAAAICQsBCwILAzgBDAQLAAsEOAICAgEAAAEJCwEHABEHIQQGBQgGAAAAAAAAAAAnAgA="],"dependencies":["0x0000000000000000000000000000000000000000000000000000000000000002","0x0000000000000000000000000000000000000000000000000000000000000001"],"digest":[131,29,40,201,77,34,214,57,161,173,80,235,179,222,106,170,36,40,167,228,158,203,186,111,92,221,123,217,230,95,165,73]}"#;

#[expect(unused)]
const PACKAGE: &str = r#"
module account::account;

use iota::package_metadata::PackageMetadataV1;

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
    let authenticator_info = iota::account::create_auth_info_v1<Account>(package, module_name, function_name);
    iota::account::create_account_v1<Account>(account, authenticator_info);
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
