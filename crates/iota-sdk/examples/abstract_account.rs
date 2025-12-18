// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::{OptionExt, Result, bail};
use iota_crypto::{IotaSigner, ed25519::Ed25519PrivateKey};
use iota_graphql_client::{Client, WaitForTx, faucet::FaucetClient};
use iota_transaction_builder::{MoveAuthenticatorArgs, Shared, SharedMut, TransactionBuilder, res};
use iota_types::{
    Address, Identifier, IdentifierRef, MovePackageData, ObjectId, ObjectOut, StructTag,
};
use rand::rngs::OsRng;

#[tokio::main]
async fn main() -> Result<()> {
    let account_id = set_up_account().await?;

    let client = Client::new_localnet();

    let from_address = Address::from(account_id);
    let to_address =
        Address::from_str("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;

    // Fund the sender address for gas payment
    let faucet = FaucetClient::new_localnet();
    if faucet.request_and_wait(from_address).await?.is_none() {
        bail!("Failed to request coins from faucet");
    };

    let mut builder = TransactionBuilder::new(from_address).with_client(&client);

    builder.send_iota(to_address, 5000000000u64);

    let txn = builder.clone().finish().await?;

    println!("Signing Digest: {}", txn.signing_digest_hex());
    println!("Txn Bytes: {}", txn.to_base64());

    builder
        .execute_with_move_authenticator(
            MoveAuthenticatorArgs::inputs(("hello", Shared(ObjectId::from_str("0x06")?))),
            WaitForTx::Finalized,
        )
        .await?;

    println!("Send IOTA via abstract account was successful!");

    Ok(())
}

async fn set_up_account() -> Result<ObjectId> {
    println!("Before");
    let package_data = serde_json::from_str::<MovePackageData>(PRECOMPILED_PACKAGE)?;
    println!("After");

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
    let mut builder = TransactionBuilder::new(sender).with_client(&client);
    builder
        // Publish the package and receive the upgrade cap
        .publish(package_data.clone())
        .name("upgrade_cap")
        // Transfer the upgrade cap to the sender address
        .transfer_objects(sender, [res("upgrade_cap")]);

    println!("hello");

    let tx = builder.finish().await?;

    println!("world");

    // Sign and execute the transaction (publish the package)
    let sig = private_key.sign_transaction(&tx)?;
    let effects = client.execute_tx(&[sig], &tx, WaitForTx::Finalized).await?;
    println!("{:?}", effects.status());

    // Wait some time for the indexer to process the tx
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Resolve UpgradeCap and PackageId via the client
    let mut account_id = None::<ObjectId>;
    let mut package_id = None::<ObjectId>;
    let mut metadata = None::<ObjectId>;
    for changed_obj in effects.as_v1().changed_objects.iter() {
        match changed_obj.output_state {
            ObjectOut::PackageWrite { version, .. } => {
                let pkg_id = changed_obj.object_id;
                println!("Package ID: {pkg_id}");
                println!("Package version: {version}");
                package_id.replace(pkg_id);
            }
            ObjectOut::ObjectWrite { .. } => {
                let obj = client.object(changed_obj.object_id, None).await?;
                if let Some(obj) = obj {
                    if obj.as_struct().type_.name == Identifier::new("PackageMetadataV1")? {
                        println!("PackageMetadataV1: {}", changed_obj.object_id);
                        metadata.replace(changed_obj.object_id);
                    }
                }
            }
            _ => continue,
        }
    }
    let Some(package_id) = package_id else {
        bail!("Missing package id");
    };
    let account_tag = StructTag {
        address: package_id.into(),
        module: IdentifierRef::const_new("account").into(),
        name: IdentifierRef::const_new("Account").into(),
        type_params: Vec::new(),
    };
    for changed_obj in effects.as_v1().changed_objects.iter() {
        match changed_obj.output_state {
            ObjectOut::ObjectWrite { .. } => {
                let object_id = changed_obj.object_id;
                let Some(obj) = client.object(object_id, None).await? else {
                    bail!("Missing object {object_id}");
                };

                if obj.as_struct().type_ == account_tag {
                    println!("Account: {object_id}");
                    account_id.replace(object_id);
                }
            }
            _ => continue,
        }
    }

    let account_id = account_id.ok_or_eyre("Missing account")?;
    let metadata_id = metadata.ok_or_eyre("Missing metadata")?;

    let mut builder = TransactionBuilder::new(sender).with_client(&client);
    builder
        .move_call(package_id, "account", "link_auth")
        .arguments((
            SharedMut(account_id),
            metadata_id,
            "account",
            "authenticate",
        ));

    println!("hello");

    let tx = builder.finish().await?;

    // Sign and execute the transaction
    let sig = private_key.sign_transaction(&tx)?;
    let effects = client.execute_tx(&[sig], &tx, WaitForTx::Finalized).await?;
    println!("{:?}", effects.status());

    Ok(account_id)
}

/// The package below, compiled and exported using --dump-bytecode-as-base64
const PRECOMPILED_PACKAGE: &str = r#"{"modules":["oRzrCwYAAAALAQASAhImAzgrBGMGBWlPB7gBmgII0gNgBrIECRC7BCoK5QQLDPAEQgAJAgkCCwINAhUCFgIZAhoBCgABDAAAAAIAAQMHAQgBAgICAAMECAAECAQABQUIAAcHAgAIBgcAABIAAQAAEwIBAAAMAwEAAQ4LAQEIAQ8JCgEIBBQEBQAGFwcBAQwIGAwNAAYGBAYDBgIIAQcIBwAECAAGCAYICAgIBQYIAAgIBggEBggDBggHAQcIBwEIBQEIAAEJAAELAgEIAAMGCAYICAgIAQsCAQkAAgkACwIBCQABCgIBCAgHQUNDT1VOVAdBY2NvdW50C0F1dGhDb250ZXh0E0F1dGhlbnRpY2F0b3JJbmZvVjEFQ2xvY2sRUGFja2FnZU1ldGFkYXRhVjEGU3RyaW5nCVR4Q29udGV4dANVSUQHYWNjb3VudAVhc2NpaQxhdXRoX2NvbnRleHQMYXV0aGVudGljYXRlBWNsb2NrEWNyZWF0ZV9hY2NvdW50X3YxE2NyZWF0ZV9hdXRoX2luZm9fdjELZHVtbXlfZmllbGQCaWQEaW5pdAlsaW5rX2F1dGgDbmV3Bm9iamVjdBBwYWNrYWdlX21ldGFkYXRhE3B1YmxpY19zaGFyZV9vYmplY3QGc3RyaW5nCHRyYW5zZmVyCnR4X2NvbnRleHQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIKAgYFaGVsbG8OaW90YTo6bWV0YWRhdGEaAQAAAAAAAAARAQxhdXRoZW50aWNhdGUBAAEAAgERCAUBAgEQAQAAAAABBQsBEQUSADgAAgEBAAAICQsBCwILAzgBDAQLAAsEOAICAgEAAAEJCwEHABEHIQQGBQgGAAAAAAAAAAAnAgA="],"dependencies":["0x0000000000000000000000000000000000000000000000000000000000000002","0x0000000000000000000000000000000000000000000000000000000000000001"],"digest":[131,29,40,201,77,34,214,57,161,173,80,235,179,222,106,170,36,40,167,228,158,203,186,111,92,221,123,217,230,95,165,73]}"#;

#[expect(unused)]
const PACKAGE: &str = r#"
module account::account;

use iota::account::AuthenticatorInfoV1CompatibilityProof;
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

/// Wrapper because of &mut UID
public fun attach_auth_info_v1<AccountType: key>(account: &mut Account, authenticator_proof: AuthenticatorInfoV1CompatibilityProof<AccountType>,) {
    iota::account::attach_auth_info_v1<AccountType>(&mut account.id, authenticator_proof);
}

public fun link_auth(account: &mut Account, package: &PackageMetadataV1, module_name: std::ascii::String, function_name: std::ascii::String) {
    let authenticator = iota::account::create_auth_info_v1<Account>(package, module_name, function_name);
    let authenticator_proof = iota::account::check_auth_info_v1_compatibility<Account>(account, authenticator);
    iota::account::attach_auth_info_v1<Account>(&mut account.id, authenticator_proof);
}

/// An unsecure example authenticator function that checks if the provided message is "hello".
#[authenticator]
public fun authenticate(
    _account: &Account,
    msg: std::ascii::String,
    _auth_ctx: &iota::auth_context::AuthContext,
    _ctx: &TxContext,
) {
    assert!(msg == std::ascii::string(b"hello"), 0);
}
"#;
