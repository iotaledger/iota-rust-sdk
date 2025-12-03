// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::{OptionExt, Result, bail};
use iota_crypto::{IotaSigner, ed25519::Ed25519PrivateKey};
use iota_graphql_client::{Client, WaitForTx, faucet::FaucetClient};
use iota_transaction_builder::{MoveAuthenticatorFnCall, TransactionBuilder, res};
use iota_types::{Address, IdentifierRef, MovePackageData, ObjectId, ObjectOut, StructTag};
use rand::rngs::OsRng;

#[tokio::main]
async fn main() -> Result<()> {
    let account_id = set_up_account().await?;

    let client = Client::new_localnet();

    let from_address = Address::from(account_id);
    let to_address =
        Address::from_str("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;

    let mut builder = TransactionBuilder::new(from_address).with_client(&client);

    builder.send_iota(to_address, 5000000000u64);

    let txn = builder.clone().finish().await?;

    println!("Signing Digest: {}", txn.signing_digest_hex());
    println!("Txn Bytes: {}", txn.to_base64());

    builder
        .execute_with_move_authenticator(
            MoveAuthenticatorFnCall::inputs(["hello"]),
            WaitForTx::Finalized,
        )
        .await?;

    println!("Send IOTA via abstract account was successful!");

    Ok(())
}

async fn set_up_account() -> Result<ObjectId> {
    let package_data = serde_json::from_str::<MovePackageData>(PRECOMPILED_PACKAGE)?;

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

    let tx = builder.finish().await?;

    // Sign and execute the transaction (publish the package)
    let sig = private_key.sign_transaction(&tx)?;
    let effects = client.execute_tx(&[sig], &tx, WaitForTx::Finalized).await?;
    println!("{:?}", effects.status());

    // Wait some time for the indexer to process the tx
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Resolve UpgradeCap and PackageId via the client
    let mut account_id = None::<ObjectId>;
    let mut package_id = None::<ObjectId>;
    for changed_obj in effects.as_v1().changed_objects.iter() {
        match changed_obj.output_state {
            ObjectOut::PackageWrite { version, .. } => {
                let pkg_id = changed_obj.object_id;
                println!("Package ID: {pkg_id}");
                println!("Package version: {version}");
                package_id.replace(pkg_id);
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

    account_id.ok_or_eyre("Missing account")
}

/// The package below, compiled and exported using --dump-bytecode-as-base64
const PRECOMPILED_PACKAGE: &str = r#"{"modules":["oRzrCwYAAAAMAQAQAhAoAzg3BG8KBXlrB+QB1wIIuwRgBpsFCRCkBSoKzgULDNkFXA21BgIACQIJAgwCFQIWAhkCGgEKAAEMAAAAAgABAwcBCAEBBAIBCAECAgIAAwgEAAQFCAAGBwIABwYHAAASAAEAAAsCAQEIABMDAQAADQQBAAELCQEBCAEODQ4BCAEPCwwBCAMUBQYABRcIAQEMBxgPEAAIBwQIBgcFBwQHAggBBwgHAAIHCAALAwEJAAQHCAAGCAYICAgIBAYIAAgIBggEBggHAQcIBwEIBQEIAAEJAAIHCAULAwEJAAILAgEIAAsDAQgAAwYIBggICAgBCwIBCQACBgkACwIBCQABCwMBCQABCgIBCAgHQUNDT1VOVAdBY2NvdW50C0F1dGhDb250ZXh0E0F1dGhlbnRpY2F0b3JJbmZvVjElQXV0aGVudGljYXRvckluZm9WMUNvbXBhdGliaWxpdHlQcm9vZhFQYWNrYWdlTWV0YWRhdGFWMQZTdHJpbmcJVHhDb250ZXh0A1VJRAdhY2NvdW50BWFzY2lpE2F0dGFjaF9hdXRoX2luZm9fdjEMYXV0aF9jb250ZXh0DGF1dGhlbnRpY2F0ZSBjaGVja19hdXRoX2luZm9fdjFfY29tcGF0aWJpbGl0eRNjcmVhdGVfYXV0aF9pbmZvX3YxC2R1bW15X2ZpZWxkAmlkBGluaXQJbGlua19hdXRoA25ldwZvYmplY3QQcGFja2FnZV9tZXRhZGF0YRNwdWJsaWNfc2hhcmVfb2JqZWN0BnN0cmluZwh0cmFuc2Zlcgp0eF9jb250ZXh0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACCgIGBWhlbGxvDmlvdGE6Om1ldGFkYXRhGgEAAAAAAAAAEQEMYXV0aGVudGljYXRlAQABAAIBEQgFAQIBEAEAAAAAAQULAREHEgA4AAIBAQAAAQULAA8ACwE4AQICAQAACg8LAQsCCwM4AgwECgAuCwQ4AwwFCwAPAAsFOAQCAwEAAAEJCwEHABEJIQQGBQgGAAAAAAAAAAAnAgAAAA=="],"dependencies":["0x0000000000000000000000000000000000000000000000000000000000000002","0x0000000000000000000000000000000000000000000000000000000000000001"],"digest":[223,80,219,23,217,194,231,59,102,57,9,33,15,53,74,70,219,155,163,116,191,171,140,77,109,87,210,234,97,113,97,213]}"#;

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
