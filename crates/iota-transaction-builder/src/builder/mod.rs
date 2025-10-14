// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Builder for Programmable Transactions.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    marker::PhantomData,
    time::Duration,
};

use iota_crypto::{IotaSigner, simple::SimpleKeypair};
use iota_graphql_client::{
    Client, DryRunResult,
    query_types::{ObjectFilter, ObjectRef, TransactionMetadata},
};
use iota_types::{
    Address, GasPayment, Identifier, ObjectId, ObjectReference, Owner, ProgrammableTransaction,
    StructTag, Transaction, TransactionEffects, TransactionExpiration, TypeTag,
};
use reqwest::Url;
use serde::Serialize;

use crate::{
    PTBArgument,
    builder::{
        gas_station::GasStationData,
        named_results::{NamedResult, NamedResults},
        ptb_arguments::PTBArgumentList,
    },
    error::Error,
    publish_type::PublishType,
    types::{MoveType, MoveTypes},
    unresolved::{
        Argument, Command, Input, InputId, InputKind, MakeMoveVector, MergeCoins, MoveCall,
        Publish, SplitCoins, TransferObjects, Upgrade,
    },
};

pub(crate) mod gas_station;
mod named_results;
/// Argument types for PTBs
pub mod ptb_arguments;

/// A transaction builder which can be used to construct [`Transaction`]s.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct TransactionBuilder<C = (), L = ()> {
    data: TransactionBuildData,
    client: C,
    last_command: PhantomData<L>,
}

/// Transaction data used to build a [`Transaction`].
#[derive(Debug, Clone)]
#[repr(C)]
pub struct TransactionBuildData {
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
    /// The map of user-defined names that map to a particular command's result.
    named_results: HashMap<String, Argument>,
    /// The data used for gas station sponsorship.
    gas_station_data: Option<GasStationData>,
}

impl TransactionBuildData {
    fn set_input(&mut self, kind: InputKind, is_gas: bool) -> Argument {
        if let Some((i, input)) = self.inputs.iter_mut().find(|(_, input)| {
            match (kind.object_id(), input.kind.object_id()) {
                (Some(id1), Some(id2)) => id1 == id2,
                (None, None) => kind == input.kind,
                _ => false,
            }
        }) {
            if is_gas {
                input.is_gas = true;
            }
            // If the new input is already resolved, replace the old one in case it was
            // unresolved
            if let new_kind @ InputKind::Input(_) = kind {
                input.kind = new_kind;
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

    /// Get the current set gas coins.
    pub fn get_gas(&self) -> Vec<ObjectId> {
        self.inputs
            .values()
            .filter_map(|i| {
                if i.is_gas {
                    i.object_id().copied()
                } else {
                    None
                }
            })
            .collect()
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
    pub fn input(&mut self, input: iota_types::Input) -> Argument {
        self.set_input(InputKind::Input(input), false)
    }

    /// Add a pure input using the BCS serialized bytes
    pub fn pure_bytes(&mut self, bytes: Vec<u8>) -> Argument {
        self.set_input(
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
    pub fn named_command(&mut self, cmd: Command, name: impl NamedResults) {
        self.command(cmd);
        name.push_named_results(self);
    }

    /// Get the value for the given string in the named results map
    pub fn get_named_command(&self, name: &str) -> Option<Argument> {
        self.named_results.get(name).copied()
    }
}

impl TransactionBuilder {
    /// Instantiate a new PTB.
    pub fn new(sender: Address) -> Self {
        TransactionBuilder {
            data: TransactionBuildData {
                inputs: Default::default(),
                commands: Default::default(),
                gas_budget: Default::default(),
                gas_price: Default::default(),
                sender,
                sponsor: Default::default(),
                expiration: Default::default(),
                named_results: Default::default(),
                gas_station_data: Default::default(),
            },
            client: (),
            last_command: PhantomData,
        }
    }

    /// Set the client to enable automatic object resolution.
    pub fn with_client(self, client: Client) -> TransactionBuilder<Client> {
        TransactionBuilder {
            data: self.data,
            client,
            last_command: self.last_command,
        }
    }
}

impl<C, L> TransactionBuilder<C, L> {
    /// Apply the given parameter and return the generated argument
    pub fn apply_argument<P: PTBArgument>(&mut self, param: P) -> Argument {
        param.arg(&mut self.data)
    }

    /// Apply the given parameters and return the generated arguments
    pub fn apply_arguments<P: PTBArgumentList>(&mut self, param: P) -> Vec<Argument> {
        param.args(&mut self.data)
    }

    fn set_input(&mut self, kind: InputKind, is_gas: bool) -> Argument {
        self.data.set_input(kind, is_gas)
    }

    fn reset(&mut self) -> &mut TransactionBuilder<C> {
        // Safe to transmute because the generic type is contained in PhantomData and
        // the struct is repr(C)
        unsafe { core::mem::transmute(self) }
    }

    fn state_change<U>(&mut self) -> &mut TransactionBuilder<C, U> {
        // Safe to transmute because the generic type is contained in PhantomData and
        // the struct is repr(C)
        unsafe { core::mem::transmute(self) }
    }

    fn cmd_state_change<U: Into<Command>>(&mut self, command: U) -> &mut TransactionBuilder<C, U> {
        self.command(command.into());
        self.state_change()
    }

    /// Get the current set gas coins.
    pub fn get_gas(&self) -> Vec<ObjectId> {
        self.data.get_gas()
    }

    /// Set the gas budget. Optional.
    pub fn gas_budget(&mut self, gas_budget: u64) -> &mut Self {
        self.data.gas_budget(gas_budget);
        self
    }

    /// Set the gas price. Optional.
    pub fn gas_price(&mut self, gas_price: u64) -> &mut Self {
        self.data.gas_price(gas_price);
        self
    }

    /// Set the sponsor. Optional.
    pub fn sponsor(&mut self, sponsor: Address) -> &mut Self {
        self.data.sponsor(sponsor);
        self
    }

    /// Set the gas station sponsor. Optional.
    pub fn gas_station_sponsor(&mut self, url: Url) -> &mut TransactionBuilder<C, GasStationData> {
        self.data.gas_station_data = Some(GasStationData::new(url));
        self.state_change()
    }

    /// Set the expiration. Optional.
    pub fn expiration(&mut self, expiration: u64) -> &mut Self {
        self.data.expiration(expiration);
        self
    }

    /// Make a value available to the transaction as an input.
    pub fn input(&mut self, input: iota_types::Input) -> Argument {
        self.data.input(input)
    }

    /// Add a pure input using the BCS serialized bytes
    pub fn pure_bytes(&mut self, bytes: Vec<u8>) -> Argument {
        self.data.pure_bytes(bytes)
    }

    /// Add a pure input
    pub fn pure<T: Serialize>(&mut self, value: T) -> Argument {
        self.data.pure(value)
    }

    /// Add a new command to the PTB
    pub fn command(&mut self, command: Command) -> Argument {
        self.data.command(command)
    }

    /// Manually set a command with an optional name
    pub fn named_command(&mut self, cmd: Command, name: impl NamedResults) {
        self.data.named_command(cmd, name);
    }

    /// Get the value for the given string in the named results map
    pub fn get_named_result(&self, name: &str) -> Option<Argument> {
        self.data.get_named_command(name)
    }

    /// Send IOTA to a recipient address.
    pub fn send_iota<T: PTBArgument>(
        &mut self,
        recipient: Address,
        amount: impl Into<Option<T>>,
    ) -> &mut TransactionBuilder<C> {
        let rec_arg = self.pure(recipient);
        let coin_arg = if let Some(amount) = amount.into() {
            let amt_arg = self.apply_argument(amount);
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
        self.reset()
    }

    /// Begin building a move call.
    pub fn move_call(
        &mut self,
        package_id: impl Into<ObjectId>,
        module: &str,
        function: &str,
    ) -> &mut TransactionBuilder<C, MoveCall> {
        self.cmd_state_change(MoveCall {
            package: package_id.into(),
            module: Identifier::new(module)
                .unwrap_or_else(|_| panic!("invalid identifier: {module}")),
            function: Identifier::new(function)
                .unwrap_or_else(|_| panic!("invalid identifier: {function}")),
            type_arguments: Default::default(),
            arguments: Default::default(),
        })
    }

    /// Publish a move package.
    pub fn publish(&mut self, kind: impl Into<PublishType>) -> &mut TransactionBuilder<C, Publish> {
        let module = match kind.into() {
            PublishType::Path(_path) => todo!("load the package from the path"),
            PublishType::Compiled(m) => m,
        };
        self.cmd_state_change(Publish {
            modules: module.modules,
            dependencies: module.dependencies,
        })
    }

    /// Transfer objects to a recipient address.
    pub fn transfer_objects<U: PTBArgumentList>(
        &mut self,
        recipient: Address,
        objects: U,
    ) -> &mut TransactionBuilder<C> {
        let objects = self.apply_arguments(objects);
        let cmd = Command::TransferObjects(TransferObjects {
            objects,
            address: self.pure(recipient),
        });
        self.command(cmd);
        self.reset()
    }

    /// Transfer some coins to a recipient address. If multiple coins are
    /// provided then they will be merged.
    pub fn send_coins<T: PTBArgumentList, U: PTBArgument>(
        &mut self,
        coins: T,
        recipient: Address,
        amount: impl Into<Option<U>>,
    ) -> &mut TransactionBuilder<C> {
        let mut coin_args = self.apply_arguments(coins);
        let coin_arg = if coin_args.is_empty() {
            return self.reset();
        } else if let [coin] = coin_args[..] {
            if let Some(amount) = amount.into() {
                let amt_arg = self.apply_argument(amount);
                self.command(Command::SplitCoins(SplitCoins {
                    coin,
                    amounts: vec![amt_arg],
                }))
            } else {
                coin
            }
        } else {
            let primary_coin = coin_args.pop().unwrap();
            let coin_arg = self.command(Command::MergeCoins(MergeCoins {
                coin: primary_coin,
                coins_to_merge: coin_args,
            }));
            if let Some(amount) = amount.into() {
                let amt_arg = self.apply_argument(amount);
                self.command(Command::SplitCoins(SplitCoins {
                    coin: coin_arg,
                    amounts: vec![amt_arg],
                }))
            } else {
                coin_arg
            }
        };
        let rec_arg = self.pure(recipient);
        self.command(Command::TransferObjects(TransferObjects {
            objects: vec![coin_arg],
            address: rec_arg,
        }));
        self.reset()
    }

    /// Merge multiple coins into one.
    pub fn merge_coins<T: PTBArgument, U: PTBArgumentList>(
        &mut self,
        primary_coin: T,
        consumed_coins: U,
    ) -> &mut TransactionBuilder<C> {
        let coin = self.apply_argument(primary_coin);
        let coins_to_merge = self.apply_arguments(consumed_coins);
        self.command(Command::MergeCoins(MergeCoins {
            coin,
            coins_to_merge,
        }));
        self.reset()
    }

    /// Split a coin into many.
    pub fn split_coins<T: PTBArgument, U: PTBArgumentList>(
        &mut self,
        coin: T,
        split_amounts: U,
    ) -> &mut TransactionBuilder<C, SplitCoins> {
        let coin = self.apply_argument(coin);
        let amounts = self.apply_arguments(split_amounts);
        self.cmd_state_change(SplitCoins { coin, amounts })
    }

    /// Upgrade a move package.
    pub fn upgrade<U: PTBArgument>(
        &mut self,
        package_id: ObjectId,
        upgrade_cap: U,
        kind: impl Into<PublishType>,
    ) -> &mut TransactionBuilder<C, Upgrade> {
        let module = match kind.into() {
            PublishType::Path(_path) => todo!("load the package from the path"),
            PublishType::Compiled(m) => m,
        };
        let ticket = self.apply_argument(upgrade_cap);
        self.cmd_state_change(Upgrade {
            modules: module.modules,
            dependencies: module.dependencies,
            package: package_id,
            ticket,
        })
    }

    /// Make a move vector from a list of elements.
    pub fn make_move_vec<T: PTBArgument + MoveType>(
        &mut self,
        elements: impl IntoIterator<Item = T>,
    ) -> &mut TransactionBuilder<C, MakeMoveVector> {
        let elements = elements
            .into_iter()
            .map(|e| self.apply_argument(e))
            .collect();
        self.cmd_state_change(MakeMoveVector {
            type_: Some(T::type_tag()),
            elements,
        })
    }
}

impl<L> TransactionBuilder<(), L> {
    /// Add a gas coin that will be consumed. Optional.
    pub fn gas(&mut self, obj_ref: ObjectReference) -> &mut Self {
        self.set_input(
            InputKind::Input(iota_types::Input::ImmutableOrOwned(obj_ref)),
            true,
        );
        self
    }

    /// Add multiple gas coins that will be consumed. Optional.
    pub fn gas_coins(&mut self, obj_refs: impl IntoIterator<Item = ObjectReference>) -> &mut Self {
        for obj_ref in obj_refs {
            self.gas(obj_ref);
        }
        self
    }

    /// Convert this builder into a transaction.
    pub fn finish(mut self) -> Result<Transaction, Error> {
        let Some(price) = self.data.gas_price else {
            return Err(Error::MissingGasPrice);
        };
        let mut inputs = Vec::new();
        let mut gas = Vec::new();
        let mut input_map = HashMap::new();
        for (id, input) in std::mem::take(&mut self.data.inputs) {
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
            .data
            .commands
            .clone()
            .into_iter()
            .map(|c| c.resolve(&input_map))
            .collect();
        Ok(Transaction {
            kind: iota_types::TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
                inputs,
                commands,
            }),
            sender: self.data.sender,
            gas_payment: GasPayment {
                objects: gas,
                owner: self.data.sponsor.unwrap_or(self.data.sender),
                price,
                budget: self.data.gas_budget.unwrap_or(0),
            },
            expiration: self.data.expiration,
        })
    }
}

impl<L> TransactionBuilder<Client, L> {
    /// Get the client used by the builder.
    pub fn get_client(&self) -> &Client {
        &self.client
    }

    /// Add a gas coin that will be consumed. Optional.
    pub fn gas(&mut self, object_id: ObjectId) -> &mut Self {
        self.set_input(InputKind::ImmutableOrOwned(object_id), true);
        self
    }

    /// Add multiple gas coins that will be consumed. Optional.
    pub fn gas_coins(&mut self, obj_ids: impl IntoIterator<Item = ObjectId>) -> &mut Self {
        for id in obj_ids {
            self.gas(id);
        }
        self
    }

    async fn resolve_ptb(&mut self, default_gas: bool) -> Result<Transaction, Error> {
        let mut inputs = Vec::new();
        let mut gas = Vec::new();
        let mut input_map = HashMap::new();

        if default_gas && !self.data.inputs.values().any(|i| i.is_gas) {
            // Some commands have arguments which cannot safely be replaced by
            // `Argument::Gas`, so we need to find any instances of
            // these and ensure that we don't use those coins
            // as gas.
            let mut unusable_object_ids = HashSet::new();
            for cmd in &self.data.commands {
                for arg in match cmd {
                    Command::MoveCall(MoveCall { arguments, .. }) => arguments.as_slice(),
                    Command::TransferObjects(TransferObjects { objects, .. }) => objects.as_slice(),
                    Command::MergeCoins(MergeCoins { coins_to_merge, .. }) => {
                        coins_to_merge.as_slice()
                    }
                    _ => &[],
                } {
                    if let Argument::Input(idx) = arg {
                        if let Some(obj_id) = self.data.inputs[idx].object_id() {
                            unusable_object_ids.insert(*obj_id);
                        }
                    }
                }
            }
            for coin in self
                .client
                .objects(
                    ObjectFilter {
                        type_: Some(StructTag::gas_coin().to_string()),
                        owner: Some(self.data.sender),
                        ..Default::default()
                    },
                    Default::default(),
                )
                .await
                .map_err(Error::Client)?
                .data
            {
                if !unusable_object_ids.contains(&coin.object_id()) {
                    self.set_input(
                        InputKind::Input(iota_types::Input::ImmutableOrOwned(coin.object_ref())),
                        true,
                    );
                }
            }
        }
        for (id, input) in std::mem::take(&mut self.data.inputs) {
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
                            Owner::Shared(v) => iota_types::Input::Shared {
                                object_id,
                                initial_shared_version: *v,
                                mutable: false,
                            },
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
            .data
            .commands
            .clone()
            .into_iter()
            .map(|c| c.resolve(&input_map))
            .collect();
        let price = match self.data.gas_price {
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
            sender: self.data.sender,
            gas_payment: GasPayment {
                objects: gas,
                owner: self.data.sponsor.unwrap_or(self.data.sender),
                price,
                budget: self.data.gas_budget.unwrap_or(0),
            },
            expiration: self.data.expiration,
        })
    }

    /// Convert this builder into a transaction.
    pub async fn finish(mut self) -> Result<Transaction, Error> {
        let mut txn = self.resolve_ptb(true).await?;
        if self.data.gas_budget.is_none() {
            let res = self
                .client
                .dry_run_tx_kind(&txn.kind, true, Default::default())
                .await
                .map_err(Error::Client)?;
            if let Some(err) = res.error {
                return Err(Error::DryRun(err));
            }
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
        let txn = self.resolve_ptb(false).await?;
        if !txn.gas_payment.objects.is_empty() && txn.gas_payment.budget == 0 {
            return Err(Error::DryRun(
                "gas coins were provided without a gas budget".to_owned(),
            ));
        }
        let gas_objects = txn
            .gas_payment
            .objects
            .iter()
            .map(|r| ObjectRef {
                address: r.object_id,
                digest: r.digest.to_base58(),
                version: r.version,
            })
            .collect::<Vec<_>>();
        let res = self
            .client
            .dry_run_tx_kind(
                &txn.kind,
                skip_checks,
                TransactionMetadata {
                    gas_objects: (!gas_objects.is_empty()).then_some(gas_objects),
                    gas_budget: (txn.gas_payment.budget != 0).then_some(txn.gas_payment.budget),
                    gas_price: Some(txn.gas_payment.price),
                    gas_sponsor: Some(txn.gas_payment.owner),
                    sender: Some(txn.sender),
                },
            )
            .await
            .map_err(Error::Client)?;
        Ok(res)
    }

    /// Execute the transaction and optionally wait for finalization. The
    /// GraphQL client will be used unless a gas station was configured, in
    /// which case the transaction will be sent to the endpoint for execution.
    pub async fn execute(
        mut self,
        keypair: &SimpleKeypair,
        wait_for_finalization: bool,
    ) -> Result<Option<TransactionEffects>, Error> {
        let gas_station_data = self.data.gas_station_data.take();
        let client = self.client.clone();
        let mut txn = self.finish().await?;

        let res = if let Some(gas_station_data) = gas_station_data {
            let digest = gas_station_data.execute_txn(&mut txn, keypair).await?;
            client
                .transaction_effects(digest)
                .await
                .map_err(Error::Client)?
        } else {
            client
                .execute_tx(
                    &[keypair.sign_transaction(&txn).map_err(Error::Signature)?],
                    &txn,
                )
                .await
                .map_err(Error::Client)?
        };

        let mut retries_left = 100;
        if wait_for_finalization {
            let digest = txn.digest();
            while retries_left > 0
                && client
                    .transaction(digest)
                    .await
                    .map_err(Error::Client)?
                    .is_none()
            {
                if retries_left == 1 {
                    return Err(Error::FinalizationTimeout(digest));
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                retries_left -= 1;
            }
        }
        Ok(res)
    }

    /// Execute the transaction with a sponsor keypair and optionally wait for
    /// finalization.
    pub async fn execute_with_sponsor(
        self,
        keypair: &SimpleKeypair,
        sponsor_keypair: &SimpleKeypair,
        wait_for_finalization: bool,
    ) -> Result<Option<TransactionEffects>, Error> {
        let client = self.client.clone();
        let txn = self.finish().await?;

        let mut signatures = vec![keypair.sign_transaction(&txn).map_err(Error::Signature)?];
        signatures.push(
            sponsor_keypair
                .sign_transaction(&txn)
                .map_err(Error::Signature)?,
        );

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

impl TransactionBuilder<(), MoveCall> {
    /// Set the call params. Optional.
    pub fn arguments(&mut self, params: impl IntoIterator<Item = Argument>) -> &mut Self {
        let Command::MoveCall(last_command) = self.data.commands.last_mut().unwrap() else {
            unreachable!();
        };
        last_command.arguments = params.into_iter().collect();
        self
    }
}

impl TransactionBuilder<Client, MoveCall> {
    /// Set the call params. Optional.
    pub fn arguments<U: PTBArgumentList>(&mut self, params: U) -> &mut Self {
        let args = self.apply_arguments(params);
        let Command::MoveCall(last_command) = self.data.commands.last_mut().unwrap() else {
            unreachable!();
        };
        last_command.arguments = args;
        self
    }
}

impl<C> TransactionBuilder<C, MoveCall> {
    /// Set the generic type arguments. Optional.
    pub fn generics<G: MoveTypes>(&mut self) -> &mut Self {
        let Command::MoveCall(last_command) = self.data.commands.last_mut().unwrap() else {
            unreachable!();
        };
        last_command.type_arguments = G::type_tags();
        self
    }

    /// Set the type arguments manually. Optional.
    pub fn type_tags(&mut self, tags: impl IntoIterator<Item = TypeTag>) -> &mut Self {
        let Command::MoveCall(last_command) = self.data.commands.last_mut().unwrap() else {
            unreachable!();
        };
        last_command.type_arguments = tags.into_iter().collect();
        self
    }
}

impl TransactionBuilder<(), Publish> {
    /// Get the package ID from the UpgradeCap so that it can be used for future
    /// commands.
    pub fn package_id(&mut self, name: impl NamedResult) -> &mut TransactionBuilder {
        let cap = self.arg();
        self.move_call(Address::TWO, "package", "upgrade_package")
            .arguments([cap])
            .name(name)
            .reset()
    }
}

impl TransactionBuilder<Client, Publish> {
    /// Get the package ID from the UpgradeCap so that it can be used for future
    /// commands.
    pub fn package_id(&mut self, name: impl NamedResult) -> &mut TransactionBuilder<Client> {
        let cap = self.arg();
        self.move_call(Address::TWO, "package", "upgrade_package")
            .arguments([cap])
            .name(name)
            .reset()
    }
}

impl<C> TransactionBuilder<C, Publish> {
    /// Finish the publish call and return the UpgradeCap.
    pub fn upgrade_cap(&mut self, name: impl NamedResult) -> &mut TransactionBuilder<C> {
        name.push_named_results(&mut self.data);

        self.reset()
    }
}

impl<C, L: Into<Command>> TransactionBuilder<C, L> {
    /// Set the name for the last command.
    pub fn name(&mut self, name: impl NamedResults) -> &mut Self {
        name.push_named_results(&mut self.data);
        self
    }

    /// Get the argument representing the last command.
    pub fn arg(&mut self) -> Argument {
        Argument::Result((self.data.commands.len() - 1) as _)
    }
}

impl<C> TransactionBuilder<C, GasStationData> {
    /// Set the gas reservation duration for a gas station sponsor.
    pub fn gas_reservation_duration(&mut self, duration: Duration) -> &mut Self {
        if let Some(data) = &mut self.data.gas_station_data {
            data.set_gas_reservation_duration(duration);
        }
        self
    }

    /// Add a header that will be passed to the gas station sponsor request.
    pub fn add_gas_station_header(
        &mut self,
        name: reqwest::header::HeaderName,
        value: reqwest::header::HeaderValue,
    ) -> &mut Self {
        if let Some(data) = &mut self.data.gas_station_data {
            data.add_header(name, value);
        }
        self
    }
}
