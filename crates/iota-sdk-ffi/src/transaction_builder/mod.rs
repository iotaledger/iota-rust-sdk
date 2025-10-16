// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::Duration,
};

use iota_transaction_builder::MovePackageData;
use iota_types::Input;

use crate::{
    crypto::simple::SimpleKeypair,
    error::Result,
    graphql::GraphQLClient,
    transaction_builder::ptb_arg::{MoveArg, PTBArgument},
    types::{
        address::Address,
        graphql::DryRunResult,
        object::ObjectId,
        struct_tag::Identifier,
        transaction::{Argument, Transaction, TransactionEffects},
        type_tag::TypeTag,
    },
};

mod ptb_arg;

/// A builder for creating transactions. Use [`finish`](Self::finish) to
/// finalize the transaction data.
#[derive(derive_more::From, uniffi::Object)]
pub struct TransactionBuilder(
    RwLock<iota_transaction_builder::TransactionBuilder<iota_graphql_client::Client>>,
);

impl TransactionBuilder {
    fn read<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&iota_transaction_builder::TransactionBuilder<iota_graphql_client::Client>) -> T,
    {
        let lock = self.0.read().expect("error reading from builder");
        f(&lock)
    }

    fn write<F, T>(&self, f: F) -> T
    where
        F: FnOnce(
            &mut iota_transaction_builder::TransactionBuilder<iota_graphql_client::Client>,
        ) -> T,
    {
        let mut lock = self.0.write().expect("error writing to builder");
        f(&mut lock)
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl TransactionBuilder {
    /// Create a new transaction builder and initialize its elements to default.
    #[uniffi::constructor(name = "init")]
    pub async fn new(sender: &Address, client: &GraphQLClient) -> Self {
        Self(
            iota_transaction_builder::TransactionBuilder::new(**sender)
                .with_client(client.inner().read().await.clone())
                .into(),
        )
    }

    /// Add a gas object to use to pay for the transaction.
    pub fn gas(self: Arc<Self>, object_id: &ObjectId) -> Arc<Self> {
        self.write(|builder| {
            builder.gas(**object_id);
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
    #[uniffi::method(default(type_args = [], arguments = [], result_refs = []))]
    pub fn move_call(
        self: Arc<Self>,
        package: &Address,
        module: &Identifier,
        function: &Identifier,
        arguments: Vec<Arc<PTBArgument>>,
        type_args: Vec<Arc<TypeTag>>,
        result_refs: Vec<String>,
    ) -> Arc<Self> {
        self.write(|builder| {
            builder
                .move_call(**package, &module.as_str(), &function.as_str())
                .arguments(arguments)
                .type_tags(type_args.into_iter().map(|v| v.0.clone()))
                .result_refs(result_refs);
        });
        self
    }

    /// Send IOTA to a recipient address.
    #[uniffi::method(default(amount = None))]
    pub fn send_iota(
        self: Arc<Self>,
        recipient: &Address,
        amount: Option<Arc<PTBArgument>>,
    ) -> Arc<Self> {
        self.write(|builder| {
            builder.send_iota::<&PTBArgument>(**recipient, amount.as_deref());
        });
        self
    }

    /// Transfer some coins to a recipient address. If multiple coins are
    /// provided then they will be merged.
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

    /// Split a coin by the provided amounts.
    #[uniffi::method(default(names = []))]
    pub fn split_coins(
        self: Arc<Self>,
        coin: &PTBArgument,
        amounts: Vec<Arc<PTBArgument>>,
        names: Vec<String>,
    ) -> Arc<Self> {
        self.write(|builder| {
            builder.split_coins(coin, amounts).result_refs(names);
        });
        self
    }

    /// Merge a list of coins into a single coin, without producing any result.
    pub fn merge_coins(
        self: Arc<Self>,
        coin: &PTBArgument,
        coins_to_merge: Vec<Arc<PTBArgument>>,
    ) -> Arc<Self> {
        self.write(|builder| {
            builder.merge_coins(coin, coins_to_merge);
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
        use iota_transaction_builder::unresolved::{Command, MakeMoveVector};
        self.write(|builder| {
            let cmd = Command::MakeMoveVector(MakeMoveVector {
                type_: Some(type_tag.0.clone()),
                elements: elements
                    .iter()
                    .map(|e| builder.apply_argument(e.as_ref()))
                    .collect(),
            });
            builder.named_command(cmd, name);
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
        modules: Vec<Vec<u8>>,
        dependencies: Vec<Arc<ObjectId>>,
        upgrade_cap_name: String,
    ) -> Arc<Self> {
        self.write(|builder| {
            builder
                .publish(MovePackageData {
                    modules,
                    dependencies: dependencies.into_iter().map(|o| **o).collect(),
                    digest: None,
                })
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
        modules: Vec<Vec<u8>>,
        dependencies: Vec<Arc<ObjectId>>,
        package: &ObjectId,
        ticket: &PTBArgument,
        name: Option<String>,
    ) -> Arc<Self> {
        self.write(|builder| {
            builder
                .upgrade(
                    **package,
                    ticket,
                    MovePackageData {
                        modules,
                        dependencies: dependencies.into_iter().map(|o| **o).collect(),
                        digest: None,
                    },
                )
                .result_refs(name);
        });
        self
    }

    /// Convert this builder into a transaction.
    pub async fn finish(&self) -> Result<Transaction> {
        Ok(Transaction(
            self.read(|builder| builder.clone().finish()).await?,
        ))
    }

    /// Dry run the transaction.
    #[uniffi::method(default(skip_checks = false))]
    pub async fn dry_run(&self, skip_checks: bool) -> Result<DryRunResult> {
        Ok(self
            .read(|builder| builder.clone().dry_run(skip_checks))
            .await?
            .into())
    }

    /// Execute the transaction and optionally wait for finalization.
    #[uniffi::method(default(wait_for_finalization = false))]
    pub async fn execute(
        &self,
        keypair: &SimpleKeypair,
        wait_for_finalization: bool,
    ) -> Result<Option<Arc<TransactionEffects>>> {
        Ok(self
            .read(|builder| builder.clone().execute(&keypair.0, wait_for_finalization))
            .await?
            .map(Into::into)
            .map(Arc::new))
    }

    /// Execute the transaction and optionally wait for finalization.
    #[uniffi::method(default(wait_for_finalization = false))]
    pub async fn execute_with_sponsor(
        &self,
        keypair: &SimpleKeypair,
        sponsor_keypair: &SimpleKeypair,
        wait_for_finalization: bool,
    ) -> Result<Option<Arc<TransactionEffects>>> {
        Ok(self
            .read(|builder| {
                builder.clone().execute_with_sponsor(
                    &keypair.0,
                    &sponsor_keypair.0,
                    wait_for_finalization,
                )
            })
            .await?
            .map(Into::into)
            .map(Arc::new))
    }
}
