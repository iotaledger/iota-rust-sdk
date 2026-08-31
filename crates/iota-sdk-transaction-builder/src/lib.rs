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
//! The Transaction Builder can be used with or without a client implementing
//! [TransactionBuilderLedgerClient]. When one is provided via the
//! [with_client](TransactionBuilder::with_client) method, the resulting builder
//! will use it to find and validate provided IDs. A ledger-only client can
//! build transactions with an explicit gas budget via
//! [finish_with_budget](TransactionBuilder::finish_with_budget). Clients that
//! also implement [TransactionBuilderSimulationClient] enable
//! [dry_run](TransactionBuilder::dry_run) and
//! [finish](TransactionBuilder::finish) with automatic gas budget estimation;
//! clients that additionally implement [TransactionBuilderExecutionClient]
//! enable [execute](TransactionBuilder::execute).
//!
//! ### Example with Client Resolution
//!
//! ```
//! # use std::str::FromStr;
//! # use iota_sdk_transaction_builder::TestClient;
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
//! # let client = TestClient;
//! let mut builder = TransactionBuilder::new(sender).with_client(client);
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
//! use iota_types::{Address, ObjectDigest, ObjectId, ObjectReference, Transaction, Version};
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
//!     digest: ObjectDigest::from_str("hSAGU3ZwDwxptd17ZK1QPDdJLhvPMfpSxe1p892GFVn")?,
//!     version: Version::from_u64(545110774),
//! };
//! let gas_coin = ObjectReference {
//!     object_id: ObjectId::from_str(
//!         "0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db",
//!     )?,
//!     digest: ObjectDigest::from_str("8ahH5RXFnK1jttQEWTypYX7MRzLuQDEXk7fhMHCyZekX")?,
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
//! - [pay](TransactionBuilder::pay): Send coins of any type to several
//!   recipients, each paired with the amount to send.
//! - [pay_iota](TransactionBuilder::pay_iota): Send IOTA coins from the gas
//!   coin to several recipients.
//! - [merge_coins](TransactionBuilder::merge_coins): Merge a list of coins into
//!   a single primary coin.
//! - [split_coins](TransactionBuilder::split_coins): Split a coin into coins of
//!   various amounts.
//! - [transfer_objects](TransactionBuilder::transfer_objects): Send objects to
//!   a recipient address.
//! - [publish_package](TransactionBuilder::publish_package): Publish a move
//!   package.
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
//! - [gas_refs](TransactionBuilder::gas_refs): Add gas coins that the caller
//!   has already resolved to references.
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
//! serialized, executed, etc. On a client without simulation support, use
//! [finish_with_budget](TransactionBuilder::finish_with_budget) instead and
//! provide the gas budget explicitly.
//!
//! Additionally, when a client is provided, the builder can directly
//! [dry_run](TransactionBuilder::dry_run) or
//! [execute](TransactionBuilder::execute) the transaction.
//!
//! When the gas payment is decided elsewhere,
//! [finish_kind](TransactionBuilder::finish_kind) returns just the
//! [TransactionKind](iota_types::TransactionKind): the inputs are resolved with
//! the client, but no gas coins are selected, no budget is estimated and no gas
//! price is fetched.
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
//! instead of using the client.
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

#[cfg(feature = "test-client")]
pub use self::builder::client::test_client::{RecordingClient, TestClient, TestClientError};
pub use self::{
    builder::{
        TransactionBuilder,
        client::{
            ObjectsPage, ProtocolConfig, TransactionBuilderClient, TransactionBuilderClientBase,
            TransactionBuilderExecutionClient, TransactionBuilderLedgerClient,
            TransactionBuilderSimulationClient, WaitForTransaction,
        },
        move_authenticator::MoveAuthenticatorBuilder,
        ptb_arguments::{PTBArgument, PTBArgumentList, Receiving, Shared, SharedMut, assigned},
        signer::TransactionSigner,
    },
    types::PureBytes,
};

#[cfg(test)]
mod tests {
    use iota_types::{Address, ObjectReference, Transaction, Version};

    use crate::TransactionBuilder;

    /// A builder with one send_coins command, shared by the client tests.
    #[cfg(feature = "test-client")]
    fn builder_with<C>(client: C) -> TransactionBuilder<C> {
        let sender = "0xc574ea804d9c1a27c886312e96c0e2c9cfd71923ebaeb3000d04b5e65fca2793"
            .parse()
            .unwrap();
        let recipient = "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900"
            .parse()
            .unwrap();
        let coin: iota_types::ObjectId =
            "0x19406ea4d9609cd9422b85e6bf2486908f790b778c757aff805241f3f609f9b4"
                .parse()
                .unwrap();
        let mut builder = TransactionBuilder::new(sender).with_client(client);
        builder.send_coins([coin], recipient, 1000u64);
        builder
    }

    #[cfg(feature = "test-client")]
    mod ledger_client {
        use iota_types::{Object, ObjectId, StructTag, Version};

        use crate::{
            ObjectsPage, TestClient, TestClientError, TransactionBuilderClientBase,
            TransactionBuilderLedgerClient,
        };

        /// Implements only [`TransactionBuilderLedgerClient`] by forwarding to
        /// [`TestClient`], to verify that building a transaction with an
        /// explicit budget requires neither simulation nor execution support.
        struct LedgerOnlyClient(TestClient);

        impl TransactionBuilderClientBase for LedgerOnlyClient {
            type Error = TestClientError;
        }

        impl TransactionBuilderLedgerClient for LedgerOnlyClient {
            async fn object(
                &self,
                object_id: ObjectId,
                version: impl Into<Option<Version>>,
            ) -> Result<Option<Object>, Self::Error> {
                self.0.object(object_id, version).await
            }

            async fn objects(
                &self,
                struct_tag: Option<StructTag>,
                owner: iota_types::Address,
                cursor: Option<Vec<u8>>,
                limit: Option<usize>,
            ) -> Result<ObjectsPage, Self::Error> {
                self.0.objects(struct_tag, owner, cursor, limit).await
            }

            async fn reference_gas_price(
                &self,
                epoch: impl Into<Option<u64>>,
            ) -> Result<Option<u64>, Self::Error> {
                self.0.reference_gas_price(epoch).await
            }
        }

        #[tokio::test]
        async fn finish_with_budget_requires_only_the_ledger_client() {
            let builder = super::builder_with(LedgerOnlyClient(TestClient));
            let txn = builder.finish_with_budget(123_456_789).await.unwrap();
            let iota_types::Transaction::V1(txn) = txn else {
                panic!("expected a V1 transaction");
            };
            assert_eq!(txn.gas_payment.budget, 123_456_789);
        }

        #[tokio::test]
        async fn finish_with_budget_overrides_the_setter_and_skips_the_clamp() {
            // 1 is below the network minimum (price * 1000), so a clamp
            // would have changed it.
            let mut builder = super::builder_with(LedgerOnlyClient(TestClient));
            builder.gas_budget(2_000_000);
            let txn = builder.finish_with_budget(1).await.unwrap();
            let iota_types::Transaction::V1(txn) = txn else {
                panic!("expected a V1 transaction");
            };
            assert_eq!(txn.gas_payment.budget, 1);
        }
    }

    #[cfg(feature = "test-client")]
    mod budget_estimation {
        use iota_types::{Object, ObjectId, StructTag, Transaction, Version};

        use crate::{
            ObjectsPage, TestClient, TestClientError, TransactionBuilderClientBase,
            TransactionBuilderLedgerClient, TransactionBuilderSimulationClient,
        };

        /// Forwards to [`TestClient`] but reports a fixed gas estimate, to
        /// exercise the estimation handling in `finish()`.
        struct FixedEstimateClient(TestClient, Option<u64>);

        impl TransactionBuilderClientBase for FixedEstimateClient {
            type Error = TestClientError;
        }

        impl TransactionBuilderLedgerClient for FixedEstimateClient {
            async fn object(
                &self,
                object_id: ObjectId,
                version: impl Into<Option<Version>>,
            ) -> Result<Option<Object>, Self::Error> {
                self.0.object(object_id, version).await
            }

            async fn objects(
                &self,
                struct_tag: Option<StructTag>,
                owner: iota_types::Address,
                cursor: Option<Vec<u8>>,
                limit: Option<usize>,
            ) -> Result<ObjectsPage, Self::Error> {
                self.0.objects(struct_tag, owner, cursor, limit).await
            }

            async fn reference_gas_price(
                &self,
                epoch: impl Into<Option<u64>>,
            ) -> Result<Option<u64>, Self::Error> {
                self.0.reference_gas_price(epoch).await
            }
        }

        impl TransactionBuilderSimulationClient for FixedEstimateClient {
            type DryRunResult = ();

            async fn estimate_transaction_budget(
                &self,
                _transaction: &Transaction,
            ) -> Result<Option<u64>, Self::Error> {
                Ok(self.1)
            }

            async fn dry_run_transaction(
                &self,
                transaction: &Transaction,
                skip_checks: bool,
            ) -> Result<Self::DryRunResult, Self::Error> {
                self.0.dry_run_transaction(transaction, skip_checks).await
            }
        }

        #[tokio::test]
        async fn an_estimate_below_the_network_minimum_is_clamped() {
            let builder = super::builder_with(FixedEstimateClient(TestClient, Some(1)));
            let txn = builder.finish().await.unwrap();
            let iota_types::Transaction::V1(txn) = txn else {
                panic!("expected a V1 transaction");
            };
            // TestClient's reference gas price is 1000, so the enforced
            // minimum is 1000 * 1000 rather than the estimated 1.
            assert_eq!(txn.gas_payment.budget, 1_000_000);
        }

        #[tokio::test]
        async fn no_estimate_and_no_budget_fails_with_missing_gas_budget() {
            let builder = super::builder_with(FixedEstimateClient(TestClient, None));
            assert!(matches!(
                builder.finish().await,
                Err(crate::error::Error::MissingGasBudget)
            ));
        }

        #[tokio::test]
        async fn an_estimate_above_the_network_minimum_is_used_as_is() {
            let builder = super::builder_with(TestClient);
            let txn = builder.finish().await.unwrap();
            let iota_types::Transaction::V1(txn) = txn else {
                panic!("expected a V1 transaction");
            };
            // TestClient's estimate, above the 1_000_000 minimum.
            assert_eq!(txn.gas_payment.budget, 50_000_000);
        }

        #[tokio::test]
        async fn a_set_budget_skips_estimation_in_finish() {
            let mut builder = super::builder_with(TestClient);
            builder.gas_budget(7_000_000);
            let txn = builder.finish().await.unwrap();
            let iota_types::Transaction::V1(txn) = txn else {
                panic!("expected a V1 transaction");
            };
            // Not TestClient's 50_000_000 estimate.
            assert_eq!(txn.gas_payment.budget, 7_000_000);
        }
    }

    #[cfg(feature = "test-client")]
    mod gas_pagination {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        use iota_types::{Object, ObjectId, StructTag, Transaction, Version};

        use crate::{
            ObjectsPage, TestClient, TestClientError, TransactionBuilderClientBase,
            TransactionBuilderLedgerClient, TransactionBuilderSimulationClient,
        };

        /// Serves gas coins in three single-coin pages and counts the
        /// `objects` calls, to pin how far automatic gas selection paginates.
        struct PagingClient {
            pages_served: Arc<AtomicUsize>,
        }

        impl TransactionBuilderClientBase for PagingClient {
            type Error = TestClientError;
        }

        impl TransactionBuilderLedgerClient for PagingClient {
            async fn object(
                &self,
                object_id: ObjectId,
                version: impl Into<Option<Version>>,
            ) -> Result<Option<Object>, Self::Error> {
                TestClient.object(object_id, version).await
            }

            async fn objects(
                &self,
                _struct_tag: Option<StructTag>,
                _owner: iota_types::Address,
                cursor: Option<Vec<u8>>,
                _limit: Option<usize>,
            ) -> Result<ObjectsPage, Self::Error> {
                self.pages_served.fetch_add(1, Ordering::SeqCst);
                let page = cursor.map_or(0, |c| c[0]);
                let coin_id = ObjectId::from_bytes([0xa0 + page; ObjectId::LENGTH]).unwrap();
                let coin = TestClient.object(coin_id, None).await?.unwrap();
                Ok(ObjectsPage {
                    data: vec![coin],
                    next_cursor: (page < 2).then(|| vec![page + 1]),
                })
            }

            async fn reference_gas_price(
                &self,
                epoch: impl Into<Option<u64>>,
            ) -> Result<Option<u64>, Self::Error> {
                TestClient.reference_gas_price(epoch).await
            }
        }

        impl TransactionBuilderSimulationClient for PagingClient {
            type DryRunResult = ();

            async fn estimate_transaction_budget(
                &self,
                transaction: &Transaction,
            ) -> Result<Option<u64>, Self::Error> {
                TestClient.estimate_transaction_budget(transaction).await
            }

            async fn dry_run_transaction(
                &self,
                transaction: &Transaction,
                skip_checks: bool,
            ) -> Result<Self::DryRunResult, Self::Error> {
                TestClient
                    .dry_run_transaction(transaction, skip_checks)
                    .await
            }
        }

        fn gas_coin_count(txn: &iota_types::Transaction) -> usize {
            let iota_types::Transaction::V1(txn) = txn else {
                panic!("expected a V1 transaction");
            };
            txn.gas_payment.objects.len()
        }

        #[tokio::test]
        async fn an_explicit_budget_stops_gas_selection_at_the_covering_page() {
            // `finish_with_budget` sets the budget before resolution, so gas
            // selection stops as soon as the first page covers it.
            let pages_served = Arc::new(AtomicUsize::new(0));
            let builder = super::builder_with(PagingClient {
                pages_served: pages_served.clone(),
            });
            let txn = builder.finish_with_budget(1000).await.unwrap();
            assert_eq!(pages_served.load(Ordering::SeqCst), 1);
            assert_eq!(gas_coin_count(&txn), 1);
        }

        #[tokio::test]
        async fn a_budget_no_single_coin_covers_accumulates_pages() {
            // Each fabricated coin holds 1e12; a 1.5e12 budget needs two.
            let pages_served = Arc::new(AtomicUsize::new(0));
            let builder = super::builder_with(PagingClient {
                pages_served: pages_served.clone(),
            });
            let txn = builder.finish_with_budget(1_500_000_000_000).await.unwrap();
            assert_eq!(pages_served.load(Ordering::SeqCst), 2);
            assert_eq!(gas_coin_count(&txn), 2);
        }

        #[tokio::test]
        async fn without_a_budget_gas_selection_walks_every_page() {
            let pages_served = Arc::new(AtomicUsize::new(0));
            let builder = super::builder_with(PagingClient {
                pages_served: pages_served.clone(),
            });
            let txn = builder.finish().await.unwrap();
            assert_eq!(pages_served.load(Ordering::SeqCst), 3);
            assert_eq!(gas_coin_count(&txn), 3);
        }
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

        let recipient = Address::random();

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
        let recipient = Address::random();
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
            sender: Address::random(),
            gas_payment: iota_types::GasPayment {
                objects: vec![],
                owner: Address::random(),
                price: 0,
                budget: 0,
            },
            expiration: Default::default(),
        });
        assert!(matches!(
            TransactionBuilder::try_from(txn),
            Err(crate::error::Error::UnsupportedTransactionKind)
        ));
    }
}
