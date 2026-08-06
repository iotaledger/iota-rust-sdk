// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use super::client_builder::{ClientTransactionBuilder, InnerClientTransactionBuilder};
use crate::{
    error::Result,
    graphql::client::GraphQLClient,
    transaction_builder::{
        Payment,
        ptb_arg::{MoveArg, PTBArgument},
        signer::TransactionSigner,
    },
    types::{
        address::Address,
        move_core::{Identifier, TypeTag},
        move_package::MovePackageData,
        object::{ObjectId, ObjectReference},
        transaction::{ProgrammableTransaction, Transaction},
    },
};

/// A builder for creating transactions. Use `finish` to finalize the
/// transaction data.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct TransactionBuilder(RwLock<iota_sdk::transaction_builder::TransactionBuilder<()>>);

impl TransactionBuilder {
    fn read<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&iota_sdk::transaction_builder::TransactionBuilder<()>) -> T,
    {
        let lock = self.0.read().expect("error reading from builder");
        f(&lock)
    }

    fn write<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&mut iota_sdk::transaction_builder::TransactionBuilder<()>) -> T,
    {
        let mut lock = self.0.write().expect("error writing to builder");
        f(&mut lock)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl TransactionBuilder {
    /// Create a new transaction builder and initialize its elements to default.
    #[uniffi::constructor]
    pub fn new(sender: &Address) -> Self {
        Self(iota_sdk::transaction_builder::TransactionBuilder::new(**sender).into())
    }

    /// Reconstruct a transaction builder from a finalized transaction.
    /// Calling `finish` on the returned builder produces a transaction equal
    /// to the input.
    ///
    /// Only programmable transactions are supported; other transaction kinds
    /// will return an error.
    #[uniffi::constructor]
    pub fn from_transaction(transaction: &Transaction) -> Result<Self> {
        Ok(Self(
            iota_sdk::transaction_builder::TransactionBuilder::try_from(transaction.0.clone())?
                .into(),
        ))
    }

    /// Create a transaction builder from a programmable transaction.
    ///
    /// The returned builder has the original inputs and commands but no
    /// sender, gas payment, sponsor, or expiration; the sender defaults to
    /// the zero address and must be set via `set_sender` before `finish`
    /// is called.
    #[uniffi::constructor]
    pub fn from_programmable_transaction(ptb: &ProgrammableTransaction) -> Self {
        Self(iota_sdk::transaction_builder::TransactionBuilder::from(ptb.0.clone()).into())
    }

    /// Use a GraphQL client to automatically resolve the transaction inputs.
    pub fn with_client(&self, client: Arc<GraphQLClient>) -> ClientTransactionBuilder {
        ClientTransactionBuilder(
            InnerClientTransactionBuilder::from(
                self.read(|builder| builder.clone().with_client(client)),
            )
            .into(),
        )
    }

    /// Set the sender address.
    pub fn set_sender(self: Arc<Self>, sender: &Address) {
        self.write(|builder| {
            builder.set_sender(**sender);
        });
    }

    /// Add gas coins that will be consumed. Optional.
    pub fn gas(self: Arc<Self>, object_refs: Vec<ObjectReference>) -> Arc<Self> {
        self.write(|builder| {
            builder.gas(object_refs.into_iter().map(|id| id.into()));
        });
        self
    }

    /// Set the gas budget for the transaction.
    pub fn gas_budget(self: Arc<Self>, budget: u64) -> Arc<Self> {
        self.write(|builder| {
            builder.gas_budget(budget);
        });
        self
    }

    /// Set the gas price for the transaction.
    pub fn gas_price(self: Arc<Self>, price: u64) -> Arc<Self> {
        self.write(|builder| {
            builder.gas_price(price);
        });
        self
    }

    /// Set the sponsor of the transaction.
    pub fn sponsor(self: Arc<Self>, sponsor: &Address) -> Arc<Self> {
        self.write(|builder| {
            builder.sponsor(**sponsor);
        });
        self
    }

    /// Set the gas station sponsor.
    #[uniffi::method(default(duration = None, headers = None))]
    pub fn gas_station_sponsor(
        self: Arc<Self>,
        url: String,
        duration: Option<Duration>,
        headers: Option<HashMap<String, Vec<String>>>,
    ) -> Arc<Self> {
        self.write(|builder| {
            let b = builder.gas_station_sponsor(url.parse().expect("invalid URL"));
            if let Some(duration) = duration {
                b.gas_reservation_duration(duration);
            }
            if let Some(headers) = headers {
                for (name, values) in headers {
                    for value in values {
                        b.add_gas_station_header(
                            name.parse().expect("invalid header name"),
                            value.parse().expect("invalid header value"),
                        );
                    }
                }
            }
        });
        self
    }

    /// Set the expiration of the transaction to be a specific epoch.
    pub fn expiration(self: Arc<Self>, epoch: u64) -> Arc<Self> {
        self.write(|builder| {
            builder.expiration(epoch);
        });
        self
    }

    // Commands

    /// Call a Move function with the given arguments.
    #[uniffi::method(default(type_args = [], arguments = [], names = []))]
    pub fn move_call(
        self: Arc<Self>,
        package: &Address,
        module: &Identifier,
        function: &Identifier,
        arguments: Vec<Arc<PTBArgument>>,
        type_args: Vec<Arc<TypeTag>>,
        names: Vec<String>,
    ) -> Arc<Self> {
        self.write(|builder| {
            builder
                .move_call(**package, &module.as_str(), &function.as_str())
                .arguments(arguments)
                .type_tags(type_args.into_iter().map(|v| v.0.clone()))
                .assign(names);
        });
        self
    }

    /// Send IOTA to a recipient address.
    ///
    /// The `amount` parameter specifies the quantity in NANOS, where 1 IOTA
    /// equals 1_000_000_000 NANOS. That amount is split from the gas coin and
    /// sent.
    pub fn send_iota(self: Arc<Self>, recipient: &Address, amount: &PTBArgument) -> Arc<Self> {
        self.write(|builder| {
            builder.send_iota(**recipient, amount);
        });
        self
    }

    /// Transfer some coins to a recipient address. If multiple coins are
    /// provided then they will be merged.
    ///
    /// The `amount` parameter specifies the quantity in NANOS, where 1 IOTA
    /// equals 1_000_000_000 NANOS.
    /// If `amount` is provided, that amount is split from the provided coins
    /// and sent.
    /// If `amount` is `None`, the entire coins are transferred.
    ///
    /// All provided coins must have the same coin type. Mixing coins of
    /// different types will result in an error.
    ///
    /// If you intend to transfer all provided coins to another address in a
    /// single transaction, consider using
    /// `TransactionBuilder::transfer_objects()` instead.
    #[uniffi::method(default(amount = None))]
    pub fn send_coins(
        self: Arc<Self>,
        coins: Vec<Arc<PTBArgument>>,
        recipient: &Address,
        amount: Option<Arc<PTBArgument>>,
    ) -> Arc<Self> {
        self.write(|builder| {
            builder.send_coins::<_, &PTBArgument>(coins, **recipient, amount.as_deref());
        });
        self
    }

    /// Transfer a list of objects to the given address, without producing any
    /// result.
    pub fn transfer_objects(
        self: Arc<Self>,
        recipient: &Address,
        objects: Vec<Arc<PTBArgument>>,
    ) -> Arc<Self> {
        self.write(|builder| {
            builder.transfer_objects(**recipient, objects);
        });
        self
    }

    /// Send coins to multiple recipients, each paired with the amount to
    /// send.
    ///
    /// The amounts specify quantities in the coins' smallest unit (NANOS for
    /// IOTA coins, where 1 IOTA equals 1_000_000_000 NANOS).
    ///
    /// The coins are merged into the first one, the amounts are split off it
    /// in a single command, and each split coin is transferred to its
    /// corresponding recipient, with one transfer command per unique
    /// recipient. The remainder stays in the first coin.
    ///
    /// All provided coins must have the same coin type. Mixing coins of
    /// different types will result in an error.
    ///
    /// To pay IOTA directly from the gas coin, use
    /// `TransactionBuilder::pay_iota()` instead.
    ///
    /// For a single recipient, consider using
    /// `TransactionBuilder::send_coins()` or `TransactionBuilder::send_iota()`
    /// instead.
    pub fn pay(self: Arc<Self>, coins: Vec<Arc<PTBArgument>>, payments: Vec<Payment>) -> Arc<Self> {
        self.write(|builder| {
            builder.pay(
                coins,
                payments.into_iter().map(|p| (**p.recipient, p.amount)),
            );
        });
        self
    }

    /// Send IOTA to multiple recipients, each paired with the amount to
    /// send.
    ///
    /// The amounts specify quantities in NANOS, where 1 IOTA equals
    /// 1_000_000_000 NANOS. They are split off the gas coin in a single
    /// command, and each split coin is transferred to its corresponding
    /// recipient, with one transfer command per unique recipient.
    ///
    /// To pay with specific coins, or with a coin type other than IOTA, use
    /// `TransactionBuilder::pay()`. For a single recipient, consider using
    /// `TransactionBuilder::send_iota()` instead.
    pub fn pay_iota(self: Arc<Self>, payments: Vec<Payment>) -> Arc<Self> {
        self.write(|builder| {
            builder.pay_iota(payments.into_iter().map(|p| (**p.recipient, p.amount)));
        });
        self
    }

    /// Split a coin by the provided amounts.
    #[uniffi::method(default(names = []))]
    pub fn split_coins(
        self: Arc<Self>,
        coin: &PTBArgument,
        amounts: Vec<Arc<PTBArgument>>,
        names: Vec<String>,
    ) -> Arc<Self> {
        self.write(|builder| {
            builder.split_coins(coin, amounts).assign(names);
        });
        self
    }

    /// Merge multiple coins into one.
    ///
    /// This method combines the balances of multiple coins of the same coin
    /// type into a single coin. The `primary_coin` will receive the balances
    /// from all `consumed_coins`. After merging, the `consumed_coins` will
    /// be consumed and no longer exist.
    pub fn merge_coins(
        self: Arc<Self>,
        primary_coin: &PTBArgument,
        consumed_coins: Vec<Arc<PTBArgument>>,
    ) -> Arc<Self> {
        self.write(|builder| {
            builder.merge_coins(primary_coin, consumed_coins);
        });
        self
    }

    /// Make a move vector from a list of elements. The elements must all be of
    /// the type indicated by `type_tag`.
    pub fn make_move_vec(
        self: Arc<Self>,
        elements: Vec<Arc<MoveArg>>,
        type_tag: &TypeTag,
        name: String,
    ) -> Arc<Self> {
        use iota_sdk::transaction_builder::unresolved::{Command, MakeMoveVector};
        self.write(|builder| {
            let cmd = Command::MakeMoveVector(MakeMoveVector {
                type_: Some(type_tag.0.clone()),
                elements: elements
                    .iter()
                    .map(|e| builder.apply_argument(e.as_ref()))
                    .collect(),
            });
            builder.assigned_command(cmd, name);
        });
        self
    }

    /// Publish a list of modules with the given dependencies. The result
    /// assigned to `upgrade_cap_name` is the `0x2::package::UpgradeCap`
    /// Move type. Note that the upgrade capability needs to be handled
    /// after this call:
    ///  - transfer it to the transaction sender or another address
    ///  - burn it
    ///  - wrap it for access control
    ///  - discard the it to make a package immutable
    ///
    /// The arguments required for this command are:
    ///  - `modules`: is the modules' bytecode to be published
    ///  - `dependencies`: is the list of IDs of the transitive dependencies of
    ///    the package
    pub fn publish(
        self: Arc<Self>,
        package_data: &MovePackageData,
        upgrade_cap_name: String,
    ) -> Arc<Self> {
        self.write(|builder| {
            builder
                .publish(package_data.0.clone())
                .upgrade_cap(upgrade_cap_name);
        });
        self
    }

    /// Upgrade a Move package.
    ///
    ///  - `modules`: is the modules' bytecode for the modules to be published
    ///  - `dependencies`: is the list of IDs of the transitive dependencies of
    ///    the package to be upgraded
    ///  - `package`: is the ID of the current package being upgraded
    ///  - `ticket`: is the upgrade ticket
    ///
    ///  To get the ticket, you have to call the
    /// `0x2::package::authorize_upgrade` function, and pass the package
    /// ID, the upgrade policy, and package digest.
    #[uniffi::method(default(name = None))]
    pub fn upgrade(
        self: Arc<Self>,
        package_id: &ObjectId,
        package_data: &MovePackageData,
        upgrade_ticket: &PTBArgument,
        name: Option<String>,
    ) -> Arc<Self> {
        self.write(|builder| {
            builder
                .upgrade(**package_id, package_data.0.clone(), upgrade_ticket)
                .assign(name);
        });
        self
    }

    /// Add stake to a validator's staking pool.
    ///
    /// This is a high-level function which will split the provided stake amount
    /// from the gas coin and then stake using the resulting coin.
    pub fn stake(self: Arc<Self>, stake: &PTBArgument, validator_address: &Address) -> Arc<Self> {
        self.write(|builder| {
            builder.stake(stake, **validator_address);
        });
        self
    }

    /// Withdraw stake from a validator's staking pool.
    pub fn unstake(self: Arc<Self>, staked_iota: &PTBArgument) -> Arc<Self> {
        self.write(|builder| {
            builder.unstake(staked_iota);
        });
        self
    }

    /// Convert this builder into a transaction.
    pub fn finish(&self) -> Result<Transaction> {
        Ok(Transaction(self.read(|builder| builder.clone().finish())?))
    }

    /// Execute the transaction using the gas station and return the JSON
    /// transaction effects. This will fail unless data is set with the
    /// `gas_station_sponsor` function.
    ///
    /// NOTE: These effects are not necessarily compatible with
    /// `TransactionEffects`
    pub async fn execute_with_gas_station(
        &self,
        signer: &TransactionSigner,
    ) -> Result<serde_json::Value> {
        Ok(self
            .read(|builder| builder.clone().execute_with_gas_station(signer))
            .await?)
    }
}

#[cfg(feature = "grpc")]
#[uniffi::export]
impl TransactionBuilder {
    /// Use a gRPC client to automatically resolve the transaction inputs.
    pub fn with_grpc_client(
        &self,
        client: Arc<crate::grpc::client::GrpcClient>,
    ) -> ClientTransactionBuilder {
        ClientTransactionBuilder(
            InnerClientTransactionBuilder::from(
                self.read(|builder| builder.clone().with_client(client)),
            )
            .into(),
        )
    }
}
