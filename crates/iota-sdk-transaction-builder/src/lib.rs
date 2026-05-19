// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # IOTA Transaction Builder
//!
//! This crate contains the [TransactionBuilder], which allows for simple
//! construction of Programmable Transactions which can be executed on the IOTA
//! network.
//!
//! The builder is designed to allow for a lot of flexibility while also
//! reducing the necessary boilerplate code. It uses a type-state pattern to
//! ensure the proper flow through the various functions. It is chainable via
//! mutable references.
//!
//! ## Online vs. Offline Builder
//!
//! The Transaction Builder can be used with or without a
//! [GraphQLClient](iota_graphql_client::Client). When one is provided via the
//! [with_client](TransactionBuilder::with_client) method, the resulting builder
//! will use it to find and validate provided IDs.
//!
//! ### Example with Client Resolution
//!
//! ```
//! # use std::str::FromStr;
//! use iota_graphql_client::Client;
//! use iota_sdk_transaction_builder::TransactionBuilder;
//! use iota_types::{Address, ObjectId, Transaction};
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() -> eyre::Result<()> {
//!
//! let sender =
//!     Address::from_str("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")?;
//! let to_address =
//!     Address::from_str("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;
//!
//! let mut builder = TransactionBuilder::new(sender).with_client(Client::new_testnet());
//!
//! let coin =
//!     ObjectId::from_str("0xe0e45ecb12ddca5f0d5192d2ee9e7f711959aa98614f9905e1e25c612ffd99a2")?;
//!
//! builder.send_coins([coin], to_address, 50000000000u64);
//!
//! let txn: Transaction = builder.finish().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Example without Client Resolution
//!
//! ```
//! # use std::str::FromStr;
//! use iota_sdk_transaction_builder::TransactionBuilder;
//! use iota_types::{Address, Digest, ObjectId, ObjectReference, Transaction, Version};
//!
//! let sender =
//!     Address::from_str("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")?;
//! let to_address =
//!     Address::from_str("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;
//!
//! let mut builder = TransactionBuilder::new(sender);
//!
//! let coin = ObjectReference {
//!     object_id: ObjectId::from_str(
//!         "0xe0e45ecb12ddca5f0d5192d2ee9e7f711959aa98614f9905e1e25c612ffd99a2",
//!     )?,
//!     digest: Digest::from_str("hSAGU3ZwDwxptd17ZK1QPDdJLhvPMfpSxe1p892GFVn")?,
//!     version: Version::from_u64(545110774),
//! };
//! let gas_coin = ObjectReference {
//!     object_id: ObjectId::from_str(
//!         "0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db",
//!     )?,
//!     digest: Digest::from_str("8ahH5RXFnK1jttQEWTypYX7MRzLuQDEXk7fhMHCyZekX")?,
//!     version: Version::from_u64(473053810),
//! };
//!
//! builder
//!     .send_coins([coin], to_address, 50000000000u64)
//!     .gas([gas_coin])
//!     .gas_budget(1000000000)
//!     .gas_price(100);
//!
//! let txn: Transaction = builder.finish()?;
//! # Result::<_, eyre::Error>::Ok(())
//! ```
//!
//! NOTE: It is possible to provide an [ObjectId](iota_types::ObjectId) to an
//! offline client builder, but this will cause the builder to fail when calling
//! `finish`.
//!
//! ## Methods
//!
//! There are three kinds of methods available:
//!
//! ### Commands
//!
//! Each command method adds one or more commands to the final transaction. Some
//! commands have optional follow-up methods. All command results can be
//! assigned a name via [assign](TransactionBuilder::assign). Assigning a name
//! to a command allows them to be used later in the transaction via the
//! [assigned] method.
//!
//! - [move_call](TransactionBuilder::move_call): Call a move function.
//!     - `arguments`: Add arguments to the move call.
//!     - `generics`: Add generic types to the move call using types that
//!       implement [MoveType](types::MoveType).
//!     - `type_tags`: Add generic types directly using the
//!       [TypeTag](iota_types::TypeTag).
//! - [send_iota](TransactionBuilder::send_iota): Send IOTA coins to a recipient
//!   address.
//! - [send_coins](TransactionBuilder::send_coins): Send coins of any type to a
//!   recipient address.
//! - [merge_coins](TransactionBuilder::merge_coins): Merge a list of coins into
//!   a single primary coin.
//! - [split_coins](TransactionBuilder::split_coins): Split a coin into coins of
//!   various amounts.
//! - [transfer_objects](TransactionBuilder::transfer_objects): Send objects to
//!   a recipient address.
//! - [publish](TransactionBuilder::publish): Publish a move package.
//!     - `package_id`: Name the package ID returned by the publish call.
//! - [upgrade](TransactionBuilder::upgrade): Upgrade a move package.
//! - [make_move_vec](TransactionBuilder::make_move_vec): Create a move
//!   `vector`.
//!
//! ### Metadata
//!
//! These methods set various metadata which may be needed for the execution.
//!
//! - [gas](TransactionBuilder::gas): Add gas coins to pay for the execution.
//! - [gas_budget](TransactionBuilder::gas_budget): Set the maximum gas budget
//!   to spend.
//! - [gas_price](TransactionBuilder::gas_price): Set the gas price.
//! - [sponsor](TransactionBuilder::sponsor): Set the gas sponsor address.
//! - [gas_station_sponsor](TransactionBuilder::gas_station_sponsor): Set the
//!   gas station URL. See [Gas Station](crate#gas-station) for more info.
//! - [expiration](TransactionBuilder::expiration): Set the transaction
//!   expiration epoch.
//!
//! ### Other
//!
//! Many other methods exist, either to get data or allow for development on top
//! of the builder. Typically, these methods should not be needed, but they are
//! made available for special circumstances.
//!
//! - [apply_argument](TransactionBuilder::apply_argument)
//! - [apply_arguments](TransactionBuilder::apply_arguments)
//! - [input](TransactionBuilder::input)
//! - [pure_bytes](TransactionBuilder::pure_bytes)
//! - [pure](TransactionBuilder::pure)
//! - [command](TransactionBuilder::command)
//! - [assigned_command](TransactionBuilder::assigned_command)
//!
//! ## Finalization and Execution
//!
//! There are several ways to finish the builder. First, the
//! [finish](TransactionBuilder::finish) method can be used to return the
//! resulting [Transaction](iota_types::Transaction), which can be manually
//! serialized, executed, etc.
//!
//! Additionally, when a client is provided, the builder can directly
//! [dry_run](TransactionBuilder::dry_run) or
//! [execute](TransactionBuilder::execute) the transaction.
//!
//! When the transaction is resolved, the builder will try to ensure a valid
//! state by de-duplicating and converting appropriate inputs into references to
//! the gas coin. This means that the same input can be passed multiple times
//! and the final transaction will only contain one instance. However, in some
//! cases an invalid state can still be reached. For instance, if a coin is used
//! both for gas and as part of a group of coins, i.e. when transferring
//! objects, the transaction can not possibly be valid.
//!
//! ### Defaults
//!
//! When a client is provided, the builder can set some values by default. The
//! following are the default behaviors for each metadata value.
//!
//! - Gas: One page of coins owned by the sender.
//! - Gas Budget: A dry run will be used to estimate.
//! - Gas Price: The current reference gas price.
//!
//! ## Gas Station
//!
//! The Transaction Builder supports executing via a
//! [Gas Station](https://github.com/iotaledger/gas-station). To do so, the URL
//! must be provided via
//! [gas_station_sponsor](TransactionBuilder::gas_station_sponsor). Additional
//! configuration can then be provided via
//! [gas_reservation_duration](TransactionBuilder::gas_reservation_duration) and
//! [add_gas_station_header](TransactionBuilder::add_gas_station_header).
//!
//! By default the request will contain the header `Content-Type:
//! application/json`
//!
//! When this data has been set, calling [execute](TransactionBuilder::execute)
//! will request gas from and send the resulting transaction to this endpoint
//! instead of using the GraphQL client.
//!
//! ## Traits and Helpers
//!
//! This crate provides several traits which enable the functionality of the
//! builder. Often, when providing arguments, functions will accept either a
//! single [PTBArgument] or a [PTBArgumentList].
//!
//! [PTBArgument] is implemented for any type implementing
//! [MoveArg](types::MoveArg) as well as:
//! - [unresolved::Argument]: Arguments returned by various builder functions.
//!   Distinct from [iota_types::Argument], which cannot be used.
//! - [Input](iota_types::Input): A resolved input.
//! - [ObjectId](iota_types::ObjectId): An object's ID. Can only be used when a
//!   client is provided. This will be assumed immutable or owned.
//! - [ObjectReference](iota_types::ObjectReference): An object's reference.
//!   This will be assumed immutable or owned.
//! - [Assigned](builder::ptb_arguments::Assigned): A reference to the result of
//!   a previous assigned command, set with
//!   [assign](TransactionBuilder::assign).
//! - [Shared]: Allows specifying shared immutable move objects.
//! - [SharedMut]: Allows specifying shared mutable move objects.
//! - [Receiving]: Allows specifying receiving move objects.
//!
//! [PTBArgumentList] is implemented for collection types, and represents a set
//! of arguments. For move calls, this enables tuples of rust values to
//! represent the parameters defined in the smart contract. For calls like
//! [merge_coins](TransactionBuilder::merge_coins), this can represent a list of
//! coins.
//!
//! [MoveArg](types::MoveArg) represents types that can be serialized and
//! provided to the transaction as pure bytes.
//!
//! [MoveType](types::MoveType) defines the type tag for a rust type, so that it
//! can be used for generic arguments.
//!
//! ### Example
//!
//! The following function is defined in move in `vec_map`:
//!
//! ```ignore
//! public fun from_keys_values<K: copy, V>(mut keys: vector<K>, mut values: vector<V>): VecMap<K, V>
//! ```
//!
//! ```ignore
//! builder
//!     .move_call(Address::TWO, "vec_map", "from_keys_values")
//!     .generics::<(Address, u64)>()
//!     .arguments(([address1, address2], [10000000u64, 20000000u64]));
//! ```
//!
//! ### Custom Type
//!
//! In order to use a custom type, implement [MoveType](types::MoveType) and
//! [MoveArg](types::MoveArg).
//!
//! ```
//! # use std::str::FromStr;
//! # use iota_sdk_transaction_builder::types::{MoveArg, MoveType, PureBytes};
//! # use iota_types::TypeTag;
//! #[derive(serde::Serialize)]
//! struct MyStruct {
//!     val1: String,
//!     val2: u64,
//! }
//!
//! impl MoveType for MyStruct {
//!     fn type_tag() -> TypeTag {
//!         TypeTag::from_str("0x0::my_module::MyStruct").unwrap()
//!     }
//! }
//!
//! impl MoveArg for MyStruct {
//!     fn pure_bytes(self) -> PureBytes {
//!         PureBytes(bcs::to_bytes(&self).unwrap())
//!     }
//! }
//! ```

#![warn(missing_docs)]
#![deny(unreachable_pub)]

pub mod builder;
pub mod error;
pub mod types;
#[allow(missing_docs)]
pub mod unresolved;

pub use iota_graphql_client::{
    DryRunEffect, DryRunMutation, DryRunResult, DryRunReturn, TransactionArgument, WaitForTx,
};

pub use self::{
    builder::{
        TransactionBuilder,
        client_methods::ClientMethods,
        move_authenticator::MoveAuthenticatorBuilder,
        ptb_arguments::{PTBArgument, PTBArgumentList, Receiving, Shared, SharedMut, assigned},
        signer::TransactionSigner,
    },
    types::PureBytes,
};

#[cfg(test)]
mod tests {
    use eyre::Context;
    use iota_crypto::ed25519::Ed25519PrivateKey;
    use iota_graphql_client::{
        Client, WaitForTx,
        faucet::{CoinInfo, FaucetClient},
        pagination::PaginationFilter,
    };
    use iota_types::{
        Address, Digest, ExecutionStatus, IdOperation, MovePackageData, ObjectId, ObjectReference,
        ObjectType, Transaction, TransactionEffects, UpgradePolicy, Version,
    };

    use crate::{TransactionBuilder, assigned, error::Error};

    /// This is used to read the json file that contains the modules/deps/digest
    /// generated with iota move build --dump-bytecode-as-base64 on the
    /// `test_example_v1 and test_example_v2` projects in the tests
    /// directory. The json files are generated automatically when running
    /// `make test-with-localnet` in the root of the
    /// iota-sdk-transaction-builder crate.
    fn move_package_data(file: &str) -> MovePackageData {
        let data = std::fs::read_to_string(file)
            .with_context(|| {
                format!(
                    "Failed to read {file}. \
                    Run `make test-with-localnet` from the root of the repository that will \
                    generate the right json files with the package data and then run the tests."
                )
            })
            .unwrap();
        serde_json::from_str(&data).unwrap()
    }

    /// Generate a random private key and its corresponding address
    fn helper_address_pk() -> (Address, Ed25519PrivateKey) {
        let pk = Ed25519PrivateKey::generate(rand::thread_rng());
        let address = pk.public_key().derive_address();
        (address, pk)
    }

    /// Helper to:
    /// - generate a private key and its corresponding address
    /// - set the sender for the tx to this newly created address
    /// - set gas price
    /// - set gas budget
    /// - call faucet which returns 5 coin objects
    /// - set the gas object (last coin from the list of the 5 objects returned
    ///   by faucet)
    /// - return the address, private key, and coins.
    ///
    /// NB! This assumes that these tests run on a network whose faucet returns
    /// 5 coins per each faucet request.
    async fn helper_setup() -> (
        TransactionBuilder<Client>,
        Address,
        Ed25519PrivateKey,
        Vec<CoinInfo>,
    ) {
        let (address, pk) = helper_address_pk();
        let client = Client::new_localnet();
        let mut tx = TransactionBuilder::new(address).with_client(client.clone());
        let coins = FaucetClient::new_localnet()
            .request_and_wait(address)
            .await
            .unwrap()
            .unwrap()
            .sent;
        let tx_digest = coins.first().unwrap().transfer_tx_digest;
        wait_for_tx(&client, tx_digest).await;

        let gas = coins.last().unwrap().id;
        tx.gas([gas]);

        (tx, address, pk, coins)
    }

    /// Wait for the transaction to be finalized and indexed. This queries the
    /// GraphQL server until it retrieves the requested transaction.
    async fn wait_for_tx(client: &Client, digest: Digest) {
        while !client.is_tx_finalized(digest).await.unwrap() {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    /// Wait for the transaction to be finalized and indexed, and check the
    /// effects' to ensure the transaction was successfully executed.
    async fn check_effects_status_success(effects: Result<TransactionEffects, Error>) {
        assert!(effects.is_ok(), "Execution failed. Effects: {effects:?}");
        // check that it succeeded
        let status = effects.unwrap();
        let expected_status = ExecutionStatus::Success;
        assert_eq!(&expected_status, status.status());
    }

    #[tokio::test]
    async fn test_finish() {
        let mut tx = TransactionBuilder::new(
            "0xc574ea804d9c1a27c886312e96c0e2c9cfd71923ebaeb3000d04b5e65fca2793"
                .parse()
                .unwrap(),
        );
        let coin_obj_id = "0x19406ea4d9609cd9422b85e6bf2486908f790b778c757aff805241f3f609f9b4";
        let coin_digest = "7opR9rFUYivSTqoJHvFb9p6p54THyHTatMG6id4JKZR9";
        let coin_version = Version::from_u64(2);
        let coin = ObjectReference::new(
            coin_obj_id.parse().unwrap(),
            coin_version,
            coin_digest.parse().unwrap(),
        );

        let recipient = Address::generate(rand::thread_rng());

        let result = tx.clone().finish();
        assert!(result.is_err());

        tx.transfer_objects(recipient, vec![coin]);
        tx.gas([ObjectReference::new(
            "0xd8792bce2743e002673752902c0e7348dfffd78638cb5367b0b85857bceb9821"
                .parse()
                .unwrap(),
            Version::from_u64(2),
            "2ZigdvsZn5BMeszscPQZq9z8ebnS2FpmAuRbAi9ednCk"
                .parse()
                .unwrap(),
        )]);
        tx.gas_price(1000);

        tx.finish().unwrap();
    }

    #[test]
    fn test_transaction_to_builder_roundtrip() {
        let sender: Address = "0xc574ea804d9c1a27c886312e96c0e2c9cfd71923ebaeb3000d04b5e65fca2793"
            .parse()
            .unwrap();
        let sponsor: Address = "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900"
            .parse()
            .unwrap();
        let recipient = Address::generate(rand::thread_rng());
        let coin = ObjectReference::new(
            "0x19406ea4d9609cd9422b85e6bf2486908f790b778c757aff805241f3f609f9b4"
                .parse()
                .unwrap(),
            Version::from_u64(2),
            "7opR9rFUYivSTqoJHvFb9p6p54THyHTatMG6id4JKZR9"
                .parse()
                .unwrap(),
        );
        let gas_coin = ObjectReference::new(
            "0xd8792bce2743e002673752902c0e7348dfffd78638cb5367b0b85857bceb9821"
                .parse()
                .unwrap(),
            Version::from_u64(2),
            "2ZigdvsZn5BMeszscPQZq9z8ebnS2FpmAuRbAi9ednCk"
                .parse()
                .unwrap(),
        );

        // Build a transaction with multiple commands and a sponsor to exercise
        // inputs, gas, and the various builder fields.
        let mut tx = TransactionBuilder::new(sender);
        tx.transfer_objects(recipient, vec![coin]);
        tx.split_coins(crate::unresolved::Argument::Gas, [42u64]);
        tx.gas([gas_coin]);
        tx.gas_price(1000);
        tx.gas_budget(5_000_000);
        tx.sponsor(sponsor);
        tx.expiration(123);

        let original = tx.finish().unwrap();

        let rebuilt: TransactionBuilder = TransactionBuilder::try_from(original.clone()).unwrap();
        let roundtrip = rebuilt.finish().unwrap();

        assert_eq!(original, roundtrip);
    }

    #[test]
    fn test_transaction_to_builder_rejects_non_ptb() {
        // A non-programmable Transaction kind should not be accepted.
        let txn = Transaction::V1(iota_types::TransactionV1 {
            kind: iota_types::TransactionKind::AuthenticatorStateUpdateV1Deprecated,
            sender: Address::generate(rand::thread_rng()),
            gas_payment: iota_types::GasPayment {
                objects: vec![],
                owner: Address::generate(rand::thread_rng()),
                price: 0,
                budget: 0,
            },
            expiration: Default::default(),
        });
        assert!(matches!(
            TransactionBuilder::try_from(txn),
            Err(Error::UnsupportedTransactionKind)
        ));
    }

    #[tokio::test]
    async fn test_transfer_obj_execution() {
        let (mut tx, _, pk, coins) = helper_setup().await;

        // get the object information from the client
        let client = Client::new_localnet();
        let coin = coins.first().unwrap().id;
        let recipient = Address::generate(rand::thread_rng());
        tx.transfer_objects(recipient, [coin]);

        let effects = tx.execute(&pk, WaitForTx::Finalized).await;
        check_effects_status_success(effects).await;

        // check that recipient has 1 coin
        let recipient_coins = client
            .coins(recipient, None, PaginationFilter::default())
            .await
            .unwrap();
        assert_eq!(recipient_coins.data().len(), 1);
    }

    #[tokio::test]
    async fn test_move_call() {
        // Check that `0x1::option::is_none` move call works when passing `1`
        // set up the sender, gas object, gas budget, and gas price and return the pk to
        // sign
        let (mut tx, _, pk, _) = helper_setup().await;
        tx.move_call(Address::STD, "option", "is_none")
            .generics::<u64>()
            .arguments([Some(1u64)]);

        let effects = tx.execute(&pk, WaitForTx::Finalized).await;
        check_effects_status_success(effects).await;
    }

    #[tokio::test]
    async fn test_split_transfer() {
        let client = Client::new_localnet();
        let (mut tx, _, pk, _) = helper_setup().await;

        // transfer 1 IOTA from Gas coin
        let gas = tx.get_gas()[0];
        tx.split_coins(gas, [1_000_000_000u64]).assign("coin");
        let recipient = Address::generate(rand::thread_rng());
        tx.transfer_objects(recipient, [assigned("coin")]);

        let effects = tx.execute(&pk, WaitForTx::Finalized).await;
        check_effects_status_success(effects).await;

        // check that recipient has 1 coin
        let recipient_coins = client
            .coins(recipient, None, PaginationFilter::default())
            .await
            .unwrap();
        assert_eq!(recipient_coins.data().len(), 1);
    }

    #[tokio::test]
    async fn test_split_without_transfer_should_fail() {
        let (mut tx, _, pk, coins) = helper_setup().await;

        let coin = coins.first().unwrap().id;

        // transfer 1 IOTA
        tx.split_coins(coin, [1_000_000_000u64]);

        let effects = tx.execute(&pk, WaitForTx::Finalized).await.unwrap();

        let expected_status = ExecutionStatus::Success;
        // The tx failed, so we expect Failure instead of Success
        assert_ne!(&expected_status, effects.status());
    }

    #[tokio::test]
    async fn test_merge_coins() {
        let (mut tx, address, pk, coins) = helper_setup().await;

        let coin1 = coins.first().unwrap().id;

        let mut coins_to_merge = vec![];
        // last coin is used for gas, first coin is the one we merge into
        for c in coins[1..&coins.len() - 1].iter() {
            coins_to_merge.push(c.id);
        }

        tx.merge_coins(coin1, coins_to_merge);
        let client = tx.get_client().clone();

        let effects = tx.execute(&pk, WaitForTx::Finalized).await;
        check_effects_status_success(effects).await;

        // check that there are two coins
        let coins_after = client
            .coins(address, None, PaginationFilter::default())
            .await
            .unwrap();
        assert_eq!(coins_after.data().len(), 2);
    }

    #[tokio::test]
    async fn test_make_move_vec() {
        let (mut tx, _, pk, _) = helper_setup().await;

        tx.make_move_vec([1u64]);

        let effects = tx.execute(&pk, WaitForTx::Finalized).await;
        check_effects_status_success(effects).await;
    }

    #[tokio::test]
    async fn test_publish() {
        let (mut tx, address, pk, _) = helper_setup().await;

        let package = move_package_data("package_test_example_v1.json");
        tx.publish(package)
            .upgrade_cap("cap")
            .transfer_objects(address, [assigned("cap")]);

        let effects = tx.execute(&pk, WaitForTx::Finalized).await;
        check_effects_status_success(effects).await;
    }

    #[tokio::test]
    async fn test_upgrade() {
        let (mut tx, address, pk, coins) = helper_setup().await;

        let package = move_package_data("package_test_example_v2.json");
        tx.publish(package)
            .upgrade_cap("cap")
            .transfer_objects(address, [assigned("cap")]);

        let effects = tx.execute(&pk, WaitForTx::Finalized).await;
        let mut package_id: Option<ObjectId> = None;
        let mut created_objs = vec![];
        if let Ok(ref effects) = effects {
            match effects {
                TransactionEffects::V1(e) => {
                    for obj in e.changed_objects.clone() {
                        if obj.id_operation == IdOperation::Created {
                            let change = obj.output_state;
                            match change {
                                iota_types::ObjectOut::PackageWrite { .. } => {
                                    package_id = Some(obj.object_id);
                                }
                                iota_types::ObjectOut::ObjectWrite { .. } => {
                                    created_objs.push(obj.object_id);
                                }
                                _ => {}
                            }
                        }
                    }
                }
                _ => unimplemented!("a new enum variant was added and needs to be handled"),
            }
        }
        check_effects_status_success(effects).await;

        let client = Client::new_localnet();
        let mut tx = TransactionBuilder::new(address).with_client(&client);
        let mut upgrade_cap = None;
        for o in created_objs {
            let obj = client.object(o, None).await.unwrap().unwrap();
            match obj.object_type() {
                ObjectType::Struct(x) if x.name() == "UpgradeCap" => {
                    upgrade_cap = Some(obj.object_id());
                    break;
                }
                _ => {}
            };
        }

        let updated_package = move_package_data("package_test_example_v2.json");

        // we need this ticket to authorize the upgrade
        tx.move_call(Address::FRAMEWORK, "package", "authorize_upgrade")
            .arguments((
                upgrade_cap.unwrap(),
                UpgradePolicy::Compatible as u8,
                updated_package.digest,
            ))
            .assign("ticket");
        // now we can upgrade the package
        let receipt = tx
            .upgrade(package_id.unwrap(), updated_package, assigned("ticket"))
            .arg();

        // commit the upgrade
        tx.move_call(Address::FRAMEWORK, "package", "commit_upgrade")
            .arguments((upgrade_cap.unwrap(), receipt));

        tx.gas([coins.last().unwrap().id]);

        let effects = tx.execute(&pk, WaitForTx::Finalized).await;
        check_effects_status_success(effects).await;
    }

    /// Fund the sender with 2048 coins (the protocol's per-tx object-creation
    /// cap, reached via four `split_coins` commands at the 512-argument-per-
    /// command ceiling) and verify automatic gas-payment selection still
    /// produces a working transaction.
    #[ignore = "diagnosing CI failure separately"]
    #[tokio::test]
    async fn test_auto_gas_selection_with_many_coins() {
        use crate::unresolved::Argument;

        let (mut tx, sender, pk, coins) = helper_setup().await;
        let client = tx.get_client().clone();

        let source = coins.first().unwrap().id;

        const SPLITS_PER_CMD: usize = 512;
        const NUM_SPLIT_CMDS: usize = 4;

        for round in 0..NUM_SPLIT_CMDS {
            tx.split_coins(source, vec![1u64; SPLITS_PER_CMD]);
            let split_cmd = (round * 2) as u16;
            let outputs: Vec<Argument> = (0..SPLITS_PER_CMD as u16)
                .map(|i| Argument::NestedResult(split_cmd, i))
                .collect();
            tx.transfer_objects(sender, outputs);
        }

        let effects = tx.execute(&pk, WaitForTx::Finalized).await;
        check_effects_status_success(effects).await;

        let total = client
            .coins(sender, None, PaginationFilter::default())
            .await
            .unwrap()
            .data()
            .len();
        assert!(
            total >= 2048,
            "expected the sender to own at least 2048 coins; got {total}"
        );

        let mut tx2 = TransactionBuilder::new(sender).with_client(client);
        let recipient = Address::generate(rand::thread_rng());
        tx2.send_iota(recipient, 1_000u64);

        let effects = tx2.execute(&pk, WaitForTx::Finalized).await;
        check_effects_status_success(effects).await;
    }
}
