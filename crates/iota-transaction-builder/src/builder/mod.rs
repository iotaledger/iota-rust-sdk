// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Builder for Programmable Transactions.

use std::collections::{BTreeMap, HashMap};

use iota_crypto::IotaSigner;
use iota_graphql_client::{Client, DryRunResult};
use iota_types::{
    Address, GasPayment, ObjectId, ObjectReference, Owner, ProgrammableTransaction, Transaction,
    TransactionEffects, TransactionExpiration,
};
use serde::Serialize;

use crate::{
    builder::{
        move_call::MoveCallCommandBuilder, named_commands::NamedCommands,
        ptb_arguments::PTBArguments, publish::PublishBuilder,
    },
    error::Error,
    publish_type::PublishType,
    types::MoveType,
    unresolved::{
        Argument, Command, Input, InputId, InputKind, MakeMoveVector, MergeCoins, SplitCoins,
        TransferObjects, Upgrade,
    },
};

mod move_call;
mod named_commands;
pub(crate) mod ptb_arguments;
mod publish;

/// A transaction builder which can be used to construct [`Transaction`]s.
#[derive(Debug, Clone)]
pub struct TransactionBuilder<C> {
    /// The inputs to the transaction.
    inputs: BTreeMap<InputId, Input>,
    /// The list of commands in the transaction. A command is a single operation
    /// in a programmable transaction.
    commands: Vec<Command>,
    /// The gas budget for the transaction.
    gas_budget: Option<u64>,
    /// The gas price for the transaction.
    gas_price: Option<u64>,
    /// The sender of the transaction.
    sender: Address,
    /// The sponsor of the transaction. If None, the sender is also the sponsor.
    sponsor: Option<Address>,
    /// The expiration of the transaction. The default value of this type is no
    /// expiration.
    expiration: TransactionExpiration,
    named_commands: HashMap<String, Argument>,
    client: C,
}

impl<C> TransactionBuilder<C> {
    /// Set the client to enable automatic object resolution.
    pub fn with_client(self, client: Client) -> TransactionBuilder<Client> {
        TransactionBuilder {
            inputs: self.inputs,
            commands: self.commands,
            gas_budget: self.gas_budget,
            gas_price: self.gas_price,
            sender: self.sender,
            sponsor: self.sponsor,
            expiration: self.expiration,
            named_commands: self.named_commands,
            client,
        }
    }

    /// Transfer IOTA to a recipient address.
    pub fn transfer_iota(
        &mut self,
        recipient: Address,
        amount: impl Into<Option<u64>> + Send,
    ) -> &mut Self {
        let rec_arg = self.pure(recipient);
        let coin_arg = if let Some(amount) = amount.into() {
            let amt_arg = self.pure(amount);
            self.command(Command::SplitCoins(SplitCoins {
                coin: Argument::Gas,
                amounts: vec![amt_arg],
            }))
        } else {
            Argument::Gas
        };
        self.command(Command::TransferObjects(TransferObjects {
            objects: vec![coin_arg],
            address: rec_arg,
        }));
        self
    }

    /// Get the current set gas coins.
    pub fn get_gas(&self) -> impl Iterator<Item = ObjectId> + '_ {
        self.inputs.values().filter_map(|i| {
            if i.is_gas {
                i.object_id().copied()
            } else {
                None
            }
        })
    }

    /// Set the gas budget. Optional.
    pub fn gas_budget(&mut self, gas_budget: u64) -> &mut Self {
        self.gas_budget = Some(gas_budget);
        self
    }

    /// Set the gas price. Optional.
    pub fn gas_price(&mut self, gas_price: u64) -> &mut Self {
        self.gas_price = Some(gas_price);
        self
    }

    /// Set the sponsor. Optional.
    pub fn sponsor(&mut self, sponsor: Address) -> &mut Self {
        self.sponsor = Some(sponsor);
        self
    }

    /// Set the expiration. Optional.
    pub fn expiration(&mut self, expiration: u64) -> &mut Self {
        self.expiration = TransactionExpiration::Epoch(expiration);
        self
    }

    /// Make a value available to the transaction as an input.
    fn input(&mut self, kind: InputKind, is_gas: bool) -> Argument {
        if let Some((i, input)) = self.inputs.iter_mut().find(|(_, input)| input.kind == kind) {
            if is_gas {
                input.is_gas = true;
            }
            return Argument::Input(*i as _);
        }
        let idx = self
            .inputs
            .last_entry()
            .map(|e| *e.key() + 1)
            .unwrap_or_default();
        self.inputs.insert(idx, Input { kind, is_gas });
        Argument::Input(idx as _)
    }

    /// Add a pure input using the BCS serialized bytes
    pub fn pure_bytes(&mut self, bytes: Vec<u8>) -> Argument {
        self.input(
            InputKind::Input(iota_types::Input::Pure { value: bytes }),
            false,
        )
    }

    /// Add a pure input
    pub fn pure<T: Serialize>(&mut self, value: T) -> Argument {
        // This serialization should never fail, so we will forego error propagation
        // here for convenience
        self.pure_bytes(bcs::to_bytes(&value).expect("bcs serialization failed"))
    }

    /// Add a new command to the PTB
    pub fn command(&mut self, command: Command) -> Argument {
        let i = self.commands.len();
        self.commands.push(command);
        Argument::Result(i as u16)
    }

    /// Manually set a command with an optional name
    pub fn named_command(&mut self, cmd: Command, name: impl NamedCommands) {
        self.command(cmd);
        name.push_named_commands(self);
    }

    /// Get the value for the given string in the named commands map
    pub fn get_named_command(&self, name: &str) -> Option<Argument> {
        self.named_commands.get(name).copied()
    }

    /// Set the name for the last command. If no commands have been set, this
    /// will do nothing.
    pub fn name(&mut self, name: impl NamedCommands) -> &mut Self {
        if self.commands.len() > 0 {
            name.push_named_commands(self);
        }
        self
    }

    /// Get the argument representing the last command. If no commands have been
    /// set then this will return `Argument::Gas`.
    pub fn arg(&self) -> iota_types::Argument {
        if self.commands.len() > 0 {
            iota_types::Argument::Result((self.commands.len() - 1) as _)
        } else {
            iota_types::Argument::Gas
        }
    }
}

impl TransactionBuilder<()> {
    /// Instantiate a new PTB.
    pub fn new(sender: Address) -> TransactionBuilder<()> {
        TransactionBuilder {
            inputs: Default::default(),
            commands: Default::default(),
            gas_budget: Default::default(),
            gas_price: Default::default(),
            sender,
            sponsor: Default::default(),
            expiration: Default::default(),
            named_commands: Default::default(),
            client: (),
        }
    }

    /// Set the gas coins that will be consumed. Optional.
    pub fn gas(&mut self, obj_ref: ObjectReference) -> &mut Self {
        self.input(
            InputKind::Input(iota_types::Input::ImmutableOrOwned(obj_ref)),
            true,
        );
        self
    }

    /// Begin building a move call.
    pub fn move_call(
        &mut self,
        package_id: ObjectId,
        module: &'static str,
        function: &'static str,
    ) -> MoveCallCommandBuilder<'_, (), (), Vec<Argument>> {
        MoveCallCommandBuilder::<(), (), Vec<Argument>>::new(self, package_id, module, function)
    }

    /// Merge multiple coins into one.
    pub fn merge_coins(
        &mut self,
        primary_coin: ObjectReference,
        consumed_coins: impl IntoIterator<Item = ObjectReference> + Send,
    ) -> &mut Self {
        let primary_coin = self.input(
            InputKind::Input(iota_types::Input::ImmutableOrOwned(primary_coin)),
            false,
        );
        let mut consumed = Vec::new();
        for coin in consumed_coins {
            consumed.push(self.input(
                InputKind::Input(iota_types::Input::ImmutableOrOwned(coin)),
                false,
            ));
        }
        self.command(Command::MergeCoins(MergeCoins {
            coin: primary_coin,
            coins_to_merge: consumed,
        }));
        self
    }

    /// Split a coin into many.
    pub fn split_coins(
        &mut self,
        coin: ObjectReference,
        split_amounts: impl IntoIterator<Item = u64> + Send,
    ) -> &mut Self {
        let coin = self.input(
            InputKind::Input(iota_types::Input::ImmutableOrOwned(coin)),
            false,
        );
        let split_amounts = split_amounts.into_iter().map(|v| self.pure(v)).collect();
        self.command(Command::SplitCoins(SplitCoins {
            coin,
            amounts: split_amounts,
        }));
        self
    }

    /// Transfer objects to a recipient address.
    pub fn transfer_objects(
        &mut self,
        recipient: Address,
        objects: impl IntoIterator<Item = ObjectReference>,
    ) -> &mut Self {
        let objects = objects
            .into_iter()
            .map(|o| {
                self.input(
                    InputKind::Input(iota_types::Input::ImmutableOrOwned(o)),
                    false,
                )
            })
            .collect();
        let cmd = Command::TransferObjects(TransferObjects {
            objects,
            address: self.pure(recipient),
        });
        self.command(cmd);
        self
    }

    /// Convert this builder into a transaction.
    pub fn finish(mut self) -> Result<Transaction, Error> {
        let Some(price) = self.gas_price else {
            return Err(Error::MissingGasPrice);
        };
        let mut inputs = Vec::new();
        let mut gas = Vec::new();
        let mut input_map = HashMap::new();
        for (id, input) in std::mem::take(&mut self.inputs) {
            match input.kind {
                InputKind::Input(inp) => {
                    if input.is_gas {
                        match inp {
                            iota_types::Input::ImmutableOrOwned(obj_ref) => gas.push(obj_ref),
                            _ => return Err(Error::WrongGasObject),
                        }
                    } else {
                        let idx = inputs.len();
                        inputs.push(inp);
                        input_map.insert(id, idx as u16);
                    }
                }
                InputKind::ImmutableOrOwned(object_id)
                | InputKind::Shared { object_id, .. }
                | InputKind::Receiving(object_id) => {
                    return Err(Error::Input(format!(
                        "object {object_id} cannot be resolved without a client"
                    )));
                }
            };
        }
        let commands = self
            .commands
            .drain(..)
            .map(|c| c.resolve(&input_map))
            .collect();
        Ok(Transaction {
            kind: iota_types::TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
                inputs,
                commands,
            }),
            sender: self.sender,
            gas_payment: GasPayment {
                objects: gas,
                owner: self.sponsor.unwrap_or(self.sender),
                price,
                budget: self.gas_budget.unwrap_or(0),
            },
            expiration: self.expiration,
        })
    }
}

impl TransactionBuilder<Client> {
    /// Get the client used by the builder.
    pub fn get_client(&self) -> &Client {
        &self.client
    }

    /// Set the gas coins that will be consumed. Optional.
    pub fn gas(&mut self, object_id: ObjectId) -> &mut Self {
        self.input(InputKind::ImmutableOrOwned(object_id), true);
        self
    }

    /// Begin building a move call.
    pub fn move_call(
        &mut self,
        package_id: impl Into<ObjectId>,
        module: &str,
        function: &str,
    ) -> MoveCallCommandBuilder<'_, Client> {
        MoveCallCommandBuilder::<Client>::new(self, package_id.into(), module, function)
    }

    /// Transfer objects to a recipient address.
    pub fn transfer_objects<U: PTBArguments>(
        &mut self,
        recipient: Address,
        objects: U,
    ) -> &mut Self {
        let objects = objects.args(self);
        let cmd = Command::TransferObjects(TransferObjects {
            objects,
            address: self.pure(recipient),
        });
        self.command(cmd);
        self
    }

    /// Merge multiple coins into one.
    pub fn merge_coins(
        &mut self,
        primary_coin: ObjectId,
        consumed_coins: impl IntoIterator<Item = ObjectId> + Send,
    ) -> &mut Self {
        let primary_coin = self.input(InputKind::ImmutableOrOwned(primary_coin), false);
        let mut consumed = Vec::new();
        for coin in consumed_coins {
            consumed.push(self.input(InputKind::ImmutableOrOwned(coin), false));
        }
        self.command(Command::MergeCoins(MergeCoins {
            coin: primary_coin,
            coins_to_merge: consumed,
        }));
        self
    }

    /// Split a coin into many.
    pub fn split_coins(
        &mut self,
        coin: ObjectId,
        split_amounts: impl IntoIterator<Item = u64> + Send,
    ) -> &mut Self {
        let coin = self.input(InputKind::ImmutableOrOwned(coin), false);
        let split_amounts = split_amounts.into_iter().map(|v| self.pure(v)).collect();
        self.command(Command::SplitCoins(SplitCoins {
            coin,
            amounts: split_amounts,
        }));
        self
    }

    /// Publish a move package. Returns the upgrade capability, if there is one.
    pub fn publish(&mut self, kind: impl Into<PublishType> + Send) -> PublishBuilder<'_> {
        PublishBuilder::new(self, kind)
    }

    /// Upgrade a move package.
    pub fn upgrade<U: PTBArguments>(
        &mut self,
        package_id: ObjectId,
        upgrade_cap: U,
        kind: impl Into<PublishType> + Send,
    ) -> &mut Self {
        let module = match kind.into() {
            PublishType::Path(_path) => todo!("load the package from the path"),
            PublishType::Compiled(m) => m,
        };
        let ticket = upgrade_cap.args(self);
        if ticket.len() != 1 {
            // TODO: Maybe there's a better way
            panic!("invalid upgrade cap");
        }
        self.command(Command::Upgrade(Upgrade {
            modules: module.modules,
            dependencies: module.dependencies,
            package: package_id,
            ticket: ticket.into_iter().next().unwrap(),
        }));
        self
    }

    /// Make a move vector from a list of elements.
    pub fn make_move_vec<U: PTBArguments + MoveType>(
        &mut self,
        elements: impl IntoIterator<Item = U>,
    ) -> &mut Self {
        let mut args = Vec::new();
        for e in elements {
            args.extend(e.args(self));
        }
        let cmd = Command::MakeMoveVector(MakeMoveVector {
            type_: Some(U::type_tag()),
            elements: args,
        });
        self.command(cmd);
        self
    }

    async fn resolve_ptb(&mut self) -> Result<Transaction, Error> {
        let mut inputs = Vec::new();
        let mut gas = Vec::new();
        let mut input_map = HashMap::new();
        for (id, input) in std::mem::take(&mut self.inputs) {
            match input.kind {
                InputKind::ImmutableOrOwned(object_id) | InputKind::Receiving(object_id) => {
                    let obj = self
                        .client
                        .object(object_id, None)
                        .await
                        .map_err(Error::Client)?
                        .ok_or_else(|| Error::Input(format!("missing object {object_id}")))?;

                    if input.is_gas {
                        let obj_ref = match obj.owner() {
                            Owner::Address(_) => {
                                ObjectReference::new(object_id, obj.version(), obj.digest())
                            }
                            _ => {
                                return Err(Error::WrongGasObject);
                            }
                        };

                        gas.push(obj_ref);
                    } else {
                        let input = match obj.owner() {
                            Owner::Address(_) | Owner::Object(_) | Owner::Immutable => {
                                iota_types::Input::ImmutableOrOwned(ObjectReference::new(
                                    object_id,
                                    obj.version(),
                                    obj.digest(),
                                ))
                            }
                            _ => {
                                return Err(Error::Input(format!(
                                    "object {object_id} was passed as owned or immutable, but is not"
                                )));
                            }
                        };
                        let idx = inputs.len();
                        inputs.push(input);
                        input_map.insert(id, idx as u16);
                    }
                }
                InputKind::Shared { object_id, mutable } => {
                    let obj = self
                        .client
                        .object(object_id, None)
                        .await
                        .map_err(Error::Client)?
                        .ok_or_else(|| Error::Input(format!("missing object {object_id}")))?;

                    let input = match obj.owner() {
                        Owner::Shared(version) => iota_types::Input::Shared {
                            object_id,
                            initial_shared_version: *version,
                            mutable,
                        },
                        _ => {
                            return Err(Error::Input(format!(
                                "object {object_id} was passed as shared, but is not"
                            )));
                        }
                    };
                    let idx = inputs.len();
                    inputs.push(input);
                    input_map.insert(id, idx as u16);
                }
                InputKind::Input(inp) => {
                    if input.is_gas {
                        match inp {
                            iota_types::Input::ImmutableOrOwned(obj_ref) => gas.push(obj_ref),
                            _ => return Err(Error::WrongGasObject),
                        }
                    } else {
                        let idx = inputs.len();
                        inputs.push(inp);
                        input_map.insert(id, idx as u16);
                    }
                }
            };
        }
        let commands = self
            .commands
            .drain(..)
            .map(|c| c.resolve(&input_map))
            .collect();
        let price = match self.gas_price {
            Some(price) => price,
            None => self
                .client
                .reference_gas_price(None)
                .await
                .map_err(Error::Client)?
                .ok_or_else(|| Error::MissingGasPrice)?,
        };
        Ok(Transaction {
            kind: iota_types::TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
                inputs,
                commands,
            }),
            sender: self.sender,
            gas_payment: GasPayment {
                objects: gas,
                owner: self.sponsor.unwrap_or(self.sender),
                price,
                budget: self.gas_budget.unwrap_or(0),
            },
            expiration: self.expiration,
        })
    }

    /// Convert this builder into a transaction.
    pub async fn finish(mut self) -> Result<Transaction, Error> {
        let mut txn = self.resolve_ptb().await?;
        if self.gas_budget.is_none() {
            let res = self
                .client
                .dry_run_tx(&txn, true)
                .await
                .map_err(Error::Client)?;
            txn.gas_payment.budget = res
                .effects
                .ok_or_else(|| Error::MissingGasBudget)?
                .gas_summary()
                .gas_used();
        }

        Ok(txn)
    }

    /// Dry run the transaction.
    pub async fn dry_run(mut self, skip_checks: bool) -> Result<DryRunResult, Error> {
        let txn = self.resolve_ptb().await?;
        let res = self
            .client
            .dry_run_tx(&txn, skip_checks)
            .await
            .map_err(Error::Client)?;
        Ok(res)
    }

    /// Execute the transaction and optionally wait for finalization.
    pub async fn execute(
        self,
        keypairs: &[iota_crypto::simple::SimpleKeypair],
        wait_for_finalization: bool,
    ) -> Result<Option<TransactionEffects>, Error> {
        let client = self.client.clone();
        let txn = self.finish().await?;
        let signatures = keypairs
            .iter()
            .map(|key| key.sign_transaction(&txn))
            .collect::<Result<Vec<_>, _>>()
            .map_err(Error::Signature)?;
        let res = client
            .execute_tx(&signatures, &txn)
            .await
            .map_err(Error::Client)?;
        if wait_for_finalization {
            while client
                .transaction(txn.digest())
                .await
                .map_err(Error::Client)?
                .is_none()
            {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        }
        Ok(res)
    }
}
