// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use crate::{
    error::Result,
    graphql::{api::transactions::WaitForTx, client::GraphQLClient, output_types::DryRunResult},
    transaction_builder::{
        Payment,
        ptb_arg::{MoveArg, PTBArgument},
        signer::TransactionSigner,
    },
    types::{
        address::Address,
        digest::Digest,
        move_core::{Identifier, TypeTag},
        move_package::{MovePackageData, UpgradePolicy},
        object::ObjectId,
        transaction::{Transaction, TransactionEffects},
    },
};

/// A builder for creating transactions which uses a GraphQL client to
/// automatically resolve inputs. Use `finish` to finalize the transaction data.
#[derive(derive_more::From, uniffi::Object)]
pub struct ClientTransactionBuilder(
    pub RwLock<iota_sdk::transaction_builder::TransactionBuilder<Arc<GraphQLClient>>>,
);

impl ClientTransactionBuilder {
    fn read<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&iota_sdk::transaction_builder::TransactionBuilder<Arc<GraphQLClient>>) -> T,
    {
        let lock = self.0.read().expect("error reading from builder");
        f(&lock)
    }

    fn write<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&mut iota_sdk::transaction_builder::TransactionBuilder<Arc<GraphQLClient>>) -> T,
    {
        let mut lock = self.0.write().expect("error writing to builder");
        f(&mut lock)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl ClientTransactionBuilder {
    /// Set the sender address.
    pub fn sender(self: Arc<Self>, sender: &Address) -> Arc<Self> {
        self.write(|builder| {
            builder.sender(**sender);
        });
        self
    }

    /// Add gas coins that will be consumed. Optional.
    pub fn gas(self: Arc<Self>, object_ids: Vec<Arc<ObjectId>>) -> Arc<Self> {
        self.write(|builder| {
            builder.gas(object_ids.into_iter().map(|id| **id));
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
    /// `ClientTransactionBuilder::pay_iota()` instead.
    ///
    /// For a single recipient, consider using
    /// `ClientTransactionBuilder::send_coins()` or
    /// `ClientTransactionBuilder::send_iota()` instead.
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
    /// `ClientTransactionBuilder::pay()`. For a single recipient, consider
    /// using `ClientTransactionBuilder::send_iota()` instead.
    pub fn pay_iota(self: Arc<Self>, payments: Vec<Payment>) -> Arc<Self> {
        self.write(|builder| {
            builder.pay_iota(payments.into_iter().map(|p| (**p.recipient, p.amount)));
        });
        self
    }

    /// Split a coin into many.
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
                type_tag: Some(type_tag.0.clone()),
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
    pub fn publish_package(
        self: Arc<Self>,
        package_data: &MovePackageData,
        upgrade_cap_name: String,
    ) -> Arc<Self> {
        self.write(|builder| {
            builder
                .publish_package(package_data.0.clone())
                .upgrade_cap(upgrade_cap_name);
        });
        self
    }

    /// Authorize a package upgrade by calling
    /// `0x2::package::authorize_upgrade`.
    ///
    /// The result assigned to `upgrade_ticket_name` is the `UpgradeTicket`
    /// expected by `ClientTransactionBuilder::upgrade()`. The digest is the
    /// digest of the package being upgraded to (`MovePackageData::digest()`).
    ///
    /// For the standard upgrade flow, use
    /// `ClientTransactionBuilder::upgrade_package()` instead.
    pub fn authorize_upgrade(
        self: Arc<Self>,
        upgrade_capability: &PTBArgument,
        upgrade_policy: &UpgradePolicy,
        digest: &Digest,
        upgrade_ticket_name: String,
    ) -> Arc<Self> {
        self.write(|builder| {
            builder
                .authorize_upgrade(upgrade_capability, upgrade_policy.as_u8(), **digest)
                .assign(upgrade_ticket_name);
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
    /// To get the ticket, use
    /// `ClientTransactionBuilder::authorize_upgrade()`. The result assigned
    /// to `name` is the `UpgradeReceipt` expected by
    /// `ClientTransactionBuilder::commit_upgrade()`.
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

    /// Commit a package upgrade by calling `0x2::package::commit_upgrade`,
    /// consuming the `UpgradeReceipt` returned by
    /// `ClientTransactionBuilder::upgrade()`.
    pub fn commit_upgrade(
        self: Arc<Self>,
        upgrade_capability: &PTBArgument,
        upgrade_receipt: &PTBArgument,
    ) -> Arc<Self> {
        self.write(|builder| {
            builder.commit_upgrade(upgrade_capability, upgrade_receipt);
        });
        self
    }

    /// Upgrade a Move package.
    ///
    /// This is a high-level function which chains
    /// `ClientTransactionBuilder::authorize_upgrade()`,
    /// `ClientTransactionBuilder::upgrade()` and
    /// `ClientTransactionBuilder::commit_upgrade()` using the digest from the
    /// provided `MovePackageData`. Use the individual functions for custom
    /// upgrade flows.
    pub fn upgrade_package(
        self: Arc<Self>,
        package_id: &ObjectId,
        package_data: &MovePackageData,
        upgrade_capability: &PTBArgument,
        upgrade_policy: &UpgradePolicy,
    ) -> Arc<Self> {
        self.write(|builder| {
            builder.upgrade_package(
                **package_id,
                package_data.0.clone(),
                upgrade_capability,
                upgrade_policy.as_u8(),
            );
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
    #[uniffi::method(default(wait_for = None))]
    pub async fn execute(
        &self,
        signer: &TransactionSigner,
        wait_for: Option<WaitForTx>,
    ) -> Result<TransactionEffects> {
        Ok(self
            .read(|builder| builder.clone().execute(signer, wait_for.map(Into::into)))
            .await?
            .into())
    }

    /// Execute the transaction and optionally wait for finalization.
    #[uniffi::method(default(wait_for = None))]
    pub async fn execute_with_sponsor(
        &self,
        signer: &TransactionSigner,
        sponsor_signer: &TransactionSigner,
        wait_for: Option<WaitForTx>,
    ) -> Result<TransactionEffects> {
        Ok(self
            .read(|builder| {
                builder.clone().execute_with_sponsor(
                    signer,
                    sponsor_signer,
                    wait_for.map(Into::into),
                )
            })
            .await?
            .into())
    }
}
