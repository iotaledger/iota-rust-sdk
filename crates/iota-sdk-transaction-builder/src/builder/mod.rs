// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Builder for Programmable Transactions.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    marker::PhantomData,
    time::Duration,
};

use iota_types::{
    Address, Coin, GasPayment, Identifier, MovePackageData, Object, ObjectId, ObjectReference,
    Owner, ProgrammableTransaction, SharedObjectReference, StructTag, Transaction,
    TransactionEffects, TransactionExpiration, TransactionKind, TransactionV1, TypeTag,
};
use reqwest::Url;
use serde::Serialize;

use crate::{
    PTBArgument, SharedMut, TransactionBuilderClient, WaitForTx,
    builder::{
        assigned_results::{AssignedResult, AssignedResults},
        gas_station::GasStationData,
        ptb_arguments::PTBArgumentList,
        signer::TransactionSigner,
    },
    error::Error,
    types::{MoveType, MoveTypes},
    unresolved::{
        Argument, Command, Input, InputId, InputKind, MakeMoveVector, MergeCoins, MoveCall,
        Publish, SplitCoins, TransferObjects, Upgrade,
    },
};

mod assigned_results;
pub(crate) mod client;
pub(crate) mod gas_station;
pub mod move_authenticator;
/// Argument types for PTBs
pub mod ptb_arguments;
pub mod signer;

const REQUEST_ADD_STAKE_FN: &str = "request_add_stake";
const REQUEST_WITHDRAW_STAKE_FN: &str = "request_withdraw_stake";

/// Protocol-config key for the (exclusive) cap on `gas_payment.objects.len()`.
const MAX_GAS_PAYMENT_OBJECTS_KEY: &str = "max_gas_payment_objects";

/// Fallback cap on `gas_payment.objects.len()` used when the protocol-config
/// value is unavailable (`max_gas_payment_objects` is 256 exclusive at the
/// time of writing, so 255 inclusive). Auto gas selection fetches the live
/// value via [`TransactionBuilderClient::protocol_config`] and falls back to
/// this if the implementation does not expose protocol config or the value
/// cannot be parsed.
const DEFAULT_MAX_GAS_PAYMENT_OBJECTS: usize = 255;

/// A transaction builder which can be used to construct [`Transaction`]s.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct TransactionBuilder<C = (), L = ()> {
    data: TransactionBuildData,
    client: C,
    last_command: PhantomData<L>,
}

/// Transaction data used to build a [`Transaction`].
#[derive(Clone, Debug)]
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
    assigned_results: HashMap<String, Argument>,
    /// The data used for gas station sponsorship.
    gas_station_data: Option<GasStationData>,
}

impl TransactionBuildData {
    fn set_sender(&mut self, sender: Address) {
        self.sender = sender;
    }

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
        self.set_input(InputKind::Input(iota_types::Input::Pure(bytes)), false)
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
    pub fn assigned_command(&mut self, cmd: Command, name: impl AssignedResults) {
        self.command(cmd);
        name.push_assigned_results(self);
    }

    /// Get the value for the given string in the assigned results map
    pub fn get_assigned_result(&self, name: &str) -> Option<Argument> {
        self.assigned_results.get(name).copied()
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
                assigned_results: Default::default(),
                gas_station_data: Default::default(),
            },
            client: (),
            last_command: PhantomData,
        }
    }

    /// Set the client to enable automatic object resolution.
    pub fn with_client<C>(self, client: C) -> TransactionBuilder<C> {
        TransactionBuilder {
            data: self.data,
            client,
            last_command: self.last_command,
        }
    }
}

impl From<ProgrammableTransaction> for TransactionBuilder {
    /// Create a [`TransactionBuilder`] from a [`ProgrammableTransaction`].
    ///
    /// The returned builder has the original inputs and commands but no
    /// sender, gas payment, sponsor, or expiration; the sender defaults to
    /// [`Address::ZERO`] and must be set with
    /// [`set_sender`](TransactionBuilder::set_sender) before
    /// [`finish`](TransactionBuilder::finish) is called.
    fn from(ptb: ProgrammableTransaction) -> Self {
        let ProgrammableTransaction {
            inputs: tx_inputs,
            commands: tx_commands,
        } = ptb;

        // Inputs are inserted with keys 0..n preserving their original index,
        // so that `Argument::Input(i)` referenced from the commands remains
        // valid without remapping.
        let inputs = tx_inputs
            .into_iter()
            .enumerate()
            .map(|(i, input)| {
                (
                    i,
                    Input {
                        kind: InputKind::Input(input),
                        is_gas: false,
                    },
                )
            })
            .collect();

        let commands = tx_commands.into_iter().map(Command::from).collect();

        TransactionBuilder {
            data: TransactionBuildData {
                inputs,
                commands,
                gas_budget: Default::default(),
                gas_price: Default::default(),
                sender: Address::ZERO,
                sponsor: Default::default(),
                expiration: Default::default(),
                assigned_results: Default::default(),
                gas_station_data: Default::default(),
            },
            client: (),
            last_command: PhantomData,
        }
    }
}

impl TryFrom<Transaction> for TransactionBuilder {
    type Error = Error;

    /// Reconstruct a [`TransactionBuilder`] from a finalized [`Transaction`].
    ///
    /// Calling [`finish`](TransactionBuilder::finish) on the returned builder
    /// produces a [`Transaction`] equal to the input.
    ///
    /// Only [`TransactionKind::Programmable`]s are supported; any
    /// other variant returns an error.
    fn try_from(tx: Transaction) -> Result<Self, Self::Error> {
        let Transaction::V1(TransactionV1 {
            kind,
            sender,
            gas_payment,
            expiration,
        }) = tx
        else {
            unimplemented!("a new Transaction enum variant was added and needs to be handled")
        };
        let TransactionKind::Programmable(ptb) = kind else {
            return Err(Error::UnsupportedTransactionKind);
        };

        let mut builder = TransactionBuilder::from(ptb);

        // Gas inputs follow the programmable inputs with subsequent keys;
        // BTreeMap ordering ensures `finish` re-emits the inputs and gas
        // vectors in the original order.
        let gas_offset = builder.data.inputs.len();
        for (i, obj_ref) in gas_payment.objects.into_iter().enumerate() {
            builder.data.inputs.insert(
                gas_offset + i,
                Input {
                    kind: InputKind::Input(iota_types::Input::ImmutableOrOwned(obj_ref)),
                    is_gas: true,
                },
            );
        }

        builder.data.sender = sender;
        builder.data.sponsor = (gas_payment.owner != sender).then_some(gas_payment.owner);
        builder.data.gas_budget = Some(gas_payment.budget);
        builder.data.gas_price = Some(gas_payment.price);
        builder.data.expiration = expiration;

        Ok(builder)
    }
}

impl<C, L> TransactionBuilder<C, L> {
    /// Set the sender address.
    pub fn set_sender(&mut self, sender: Address) {
        self.data.set_sender(sender);
    }

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
    pub fn assigned_command(&mut self, cmd: Command, name: impl AssignedResults) {
        self.data.assigned_command(cmd, name);
    }

    /// Get the value for the given string in the assigned results map
    pub fn get_assigned_result(&self, name: &str) -> Option<Argument> {
        self.data.get_assigned_result(name)
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

    /// Transfer objects to a recipient address.
    ///
    /// # Example
    ///
    /// ```
    /// # use iota_sdk_transaction_builder::TestClient;
    /// use std::str::FromStr;
    ///
    /// use iota_sdk_transaction_builder::{TransactionBuilder, assigned};
    /// use iota_types::{Address, ObjectDigest, ObjectId, ObjectReference, Transaction, Version};
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> eyre::Result<()> {
    ///
    /// # let client = TestClient;
    /// let sender =
    ///     Address::from_str("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")?;
    ///
    /// let mut builder = TransactionBuilder::new(sender).with_client(client);
    ///
    /// # builder
    /// #     .split_coins(
    /// #         ObjectId::from_str(
    /// #             "0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc",
    /// #         )?,
    /// #         [1000u64],
    /// #     )
    /// #     .assign(("coin"));
    ///
    /// builder.transfer_objects(
    ///     Address::from_str("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?,
    ///     (
    ///         // ObjectIds can be passed when a client is provided
    ///         ObjectId::from_str(
    ///             "0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db",
    ///         )?,
    ///         // ObjectReferences are always allowed, though they must be correct
    ///         ObjectReference {
    ///             object_id: ObjectId::from_str(
    ///                 "0xe0e45ecb12ddca5f0d5192d2ee9e7f711959aa98614f9905e1e25c612ffd99a2",
    ///             )?,
    ///             digest: ObjectDigest::from_str("hSAGU3ZwDwxptd17ZK1QPDdJLhvPMfpSxe1p892GFVn")?,
    ///             version: Version::from_u64(545110774),
    ///         },
    ///         // The result of a previous command can also be used
    ///         assigned("coin"),
    ///     ),
    /// );
    ///
    /// let txn: Transaction = builder.finish().await?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Send IOTA to a recipient address.
    ///
    /// The `amount` parameter specifies the quantity in NANOS, where 1 IOTA
    /// equals 1_000_000_000 NANOS. That amount is split from the gas coin and
    /// sent.
    ///
    /// # Example
    ///
    /// ```
    /// # use iota_sdk_transaction_builder::TestClient;
    /// use iota_sdk_transaction_builder::TransactionBuilder;
    /// use iota_types::Address;
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> eyre::Result<()> {
    /// # let client = TestClient;
    /// let from_address =
    ///     Address::from_hex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")?;
    /// let to_address =
    ///     Address::from_hex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;
    ///
    /// let mut builder = TransactionBuilder::new(from_address).with_client(client);
    /// builder.send_iota(to_address, 5000000000u64);
    /// let txn = builder.finish().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn send_iota<T: PTBArgument>(
        &mut self,
        recipient: Address,
        amount: T,
    ) -> &mut TransactionBuilder<C> {
        let rec_arg = self.pure(recipient);
        let amt_arg = self.apply_argument(amount);
        let coin_arg = self.command(Command::SplitCoins(SplitCoins {
            coin: Argument::Gas,
            amounts: vec![amt_arg],
        }));
        self.command(Command::TransferObjects(TransferObjects {
            objects: vec![coin_arg],
            address: rec_arg,
        }));
        self.reset()
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
    /// [`TransactionBuilder::transfer_objects()`] instead.
    ///
    /// # Example
    ///
    /// ```
    /// # use iota_sdk_transaction_builder::TestClient;
    /// use iota_sdk_transaction_builder::TransactionBuilder;
    /// use iota_types::{Address, ObjectId};
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> eyre::Result<()> {
    /// # let client = TestClient;
    /// let from_address =
    ///     Address::from_hex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")?;
    /// let to_address =
    ///     Address::from_hex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;
    ///
    /// // This is a coin of type
    /// // 0xfce9c14e5f0c2b65787debb8145a33a4a2fc83152e8939000b862e174bc86bb8::cert::CERT
    /// let coin =
    ///     ObjectId::from_hex("0xe0e45ecb12ddca5f0d5192d2ee9e7f711959aa98614f9905e1e25c612ffd99a2")?;
    ///
    /// let mut builder = TransactionBuilder::new(from_address).with_client(client);
    /// builder.send_coins([coin], to_address, 50000000000u64);
    /// let txn = builder.finish().await?;
    /// #   Ok(())
    /// # }
    /// ```
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
    ///
    /// This method combines the balances of multiple coins of the same coin
    /// type into a single coin. The `primary_coin` will receive the balances
    /// from all `consumed_coins`. After merging, the `consumed_coins` will
    /// be consumed and no longer exist.
    ///
    /// # Example
    ///
    /// ```
    /// # use iota_sdk_transaction_builder::TestClient;
    /// use iota_sdk_transaction_builder::TransactionBuilder;
    /// use iota_types::{Address, ObjectId};
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> eyre::Result<()> {
    /// # let client = TestClient;
    /// let sender =
    ///     Address::from_hex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")?;
    ///
    /// let coin_0 =
    ///     ObjectId::from_hex("0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc")?;
    /// let coin_1 =
    ///     ObjectId::from_hex("0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db")?;
    ///
    /// let mut builder = TransactionBuilder::new(sender).with_client(client);
    /// builder.merge_coins(coin_0, [coin_1]);
    /// let txn = builder.finish().await?;
    /// # Ok(())
    /// # }
    /// ```
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
    ///
    /// # Example
    ///
    /// ```
    /// # use iota_sdk_transaction_builder::TestClient;
    /// use iota_sdk_transaction_builder::{TransactionBuilder, assigned};
    /// use iota_types::{Address, ObjectId};
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> eyre::Result<()> {
    /// # let client = TestClient;
    /// let sender =
    ///     Address::from_hex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")?;
    /// let coin =
    ///     ObjectId::from_hex("0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc")?;
    ///
    /// let mut builder = TransactionBuilder::new(sender).with_client(client);
    /// builder
    ///     .split_coins(coin, [1000u64, 2000, 3000])
    ///     .assign(("coin1", "coin2", "coin3"))
    ///     .transfer_objects(
    ///         sender,
    ///         (assigned("coin1"), assigned("coin2"), assigned("coin3")),
    ///     );
    /// let txn = builder.finish().await?;
    /// #    Ok(())
    /// # }
    /// ```
    pub fn split_coins<T: PTBArgument, U: PTBArgumentList>(
        &mut self,
        coin: T,
        split_amounts: U,
    ) -> &mut TransactionBuilder<C, SplitCoins> {
        let coin = self.apply_argument(coin);
        let amounts = self.apply_arguments(split_amounts);
        self.cmd_state_change(SplitCoins { coin, amounts })
    }

    /// Publish a move package.
    pub fn publish(
        &mut self,
        package_data: MovePackageData,
    ) -> &mut TransactionBuilder<C, Publish> {
        self.cmd_state_change(Publish {
            modules: package_data.modules,
            dependencies: package_data.dependencies,
        })
    }

    /// Upgrade a move package.
    pub fn upgrade<U: PTBArgument>(
        &mut self,
        package_id: ObjectId,
        package_data: MovePackageData,
        upgrade_ticket: U,
    ) -> &mut TransactionBuilder<C, Upgrade> {
        let ticket = self.apply_argument(upgrade_ticket);
        self.cmd_state_change(Upgrade {
            modules: package_data.modules,
            dependencies: package_data.dependencies,
            package: package_id,
            ticket,
        })
    }

    /// Add stake to a validator's staking pool.
    ///
    /// This is a high-level function which will split the provided stake amount
    /// from the gas coin and then stake using the resulting coin.
    ///
    /// # Example
    ///
    /// ```
    /// # use iota_sdk_transaction_builder::TestClient;
    /// use iota_sdk_transaction_builder::TransactionBuilder;
    /// use iota_types::{Address, ObjectId};
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> eyre::Result<()> {
    /// # let client = TestClient;
    /// let sender =
    ///     Address::from_hex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")?;
    /// # let validator_address = Address::ZERO;
    ///
    /// let mut builder = TransactionBuilder::new(sender).with_client(client);
    /// builder.stake(1000000000u64, validator_address);
    /// let txn = builder.finish().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn stake<S: PTBArgument>(
        &mut self,
        stake_amount: S,
        validator_address: Address,
    ) -> &mut Self {
        let coin = self.split_coins(Argument::Gas, [stake_amount]).arg();
        self.move_call(
            Address::SYSTEM,
            Identifier::IOTA_SYSTEM_MODULE.as_str(),
            REQUEST_ADD_STAKE_FN,
        )
        .arguments((SharedMut(ObjectId::SYSTEM_STATE), coin, validator_address))
        .state_change()
    }

    /// Withdraw stake from a validator's staking pool.
    ///
    /// # Example
    ///
    /// ```
    /// # use iota_sdk_transaction_builder::TestClient;
    /// use iota_sdk_transaction_builder::TransactionBuilder;
    /// use iota_types::{Address, ObjectId};
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> eyre::Result<()> {
    /// # let client = TestClient;
    /// let sender =
    ///     Address::from_hex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")?;
    /// // This is a 0x3::staking_pool::StakedIota owned by the sender
    /// let staked_iota =
    ///     ObjectId::from_hex("0x13e8d0b5cdec156e44c0834274a431505954eb27a8f774a7f9044c2908c1c494")?;
    ///
    /// let mut builder = TransactionBuilder::new(sender).with_client(client);
    /// builder.unstake(staked_iota);
    /// let txn = builder.finish().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn unstake<S: PTBArgument>(&mut self, staked_iota: S) -> &mut Self {
        self.move_call(
            Address::SYSTEM,
            Identifier::IOTA_SYSTEM_MODULE.as_str(),
            REQUEST_WITHDRAW_STAKE_FN,
        )
        .arguments((SharedMut(ObjectId::SYSTEM_STATE), staked_iota))
        .state_change()
    }

    /// Make a move vector from a list of elements.
    ///
    /// Often it is possible (and more efficient) to pass a rust slice or `Vec`
    /// instead of calling this function, which will serialize the bytes into a
    /// move vector pure argument.
    ///
    /// # Example
    ///
    /// ```
    /// # use iota_sdk_transaction_builder::TestClient;
    /// use std::str::FromStr;
    ///
    /// use iota_sdk_transaction_builder::{TransactionBuilder, assigned};
    /// use iota_types::{Address, Transaction};
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> eyre::Result<()> {
    /// # let client = TestClient;
    /// let sender = "0x71b4b4f171b4355ff691b7c470579cf1a926f96f724e5f9a30efc4b5f75d085e".parse()?;
    ///
    /// let mut builder = TransactionBuilder::new(sender).with_client(client);
    ///
    /// let address1 =
    ///     Address::from_str("0xde49ea53fbadee67d3e35a097cdbea210b659676fc680a0b0c5f11d0763d375e")?;
    /// let address2 =
    ///     Address::from_str("0xe512234aa4ef6184c52663f09612b68f040dd0c45de037d96190a071ca5525b3")?;
    ///
    /// builder
    ///     .make_move_vec([address1, address2])
    ///     .assign("addresses")
    ///     .move_call(Address::FRAMEWORK, "vec_map", "from_keys_values")
    ///     .generics::<(Address, u64)>()
    ///     .arguments((assigned("addresses"), [10000000u64, 20000000u64]));
    ///
    /// let txn: Transaction = builder.finish().await?;
    /// # Ok(())
    /// # }
    /// ```
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
    /// Add gas coins that will be consumed. Optional.
    ///
    /// # Example
    ///
    /// ```
    /// use std::str::FromStr;
    ///
    /// use iota_sdk_transaction_builder::{TransactionBuilder, assigned, unresolved};
    /// use iota_types::{Address, ObjectDigest, ObjectId, ObjectReference, Transaction, Version};
    ///
    /// let sender =
    ///     Address::from_str("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")?;
    ///
    /// let mut builder = TransactionBuilder::new(sender);
    ///
    /// let gas_coin1 = ObjectReference {
    ///     object_id: ObjectId::from_str(
    ///         "0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc",
    ///     )?,
    ///     digest: ObjectDigest::from_str("CPpQZqyHZcG2Pb9gZyikbc8dEuyipXHR6ihnfe9iYiMt")?,
    ///     version: Version::from_u64(473053811),
    /// };
    /// let gas_coin2 = ObjectReference {
    ///     object_id: ObjectId::from_str(
    ///         "0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db",
    ///     )?,
    ///     digest: ObjectDigest::from_str("8ahH5RXFnK1jttQEWTypYX7MRzLuQDEXk7fhMHCyZekX")?,
    ///     version: Version::from_u64(473053810),
    /// };
    ///
    /// builder
    ///     .split_coins(unresolved::Argument::Gas, [1000u64])
    ///     .gas([gas_coin1, gas_coin2])
    ///     .gas_budget(1000000000)
    ///     .gas_price(100);
    ///
    /// let txn: Transaction = builder.finish()?;
    /// # Result::<_, eyre::Error>::Ok(())
    /// ```
    pub fn gas(&mut self, obj_refs: impl IntoIterator<Item = ObjectReference>) -> &mut Self {
        for obj_ref in obj_refs {
            self.set_input(
                InputKind::Input(iota_types::Input::ImmutableOrOwned(obj_ref)),
                true,
            );
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
        Ok(TransactionV1 {
            kind: iota_types::TransactionKind::Programmable(ProgrammableTransaction {
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
        }
        .into())
    }

    /// Execute the transaction using the gas station and return the JSON
    /// transaction effects. This will fail unless data is set with
    /// [`Self::gas_station_sponsor`].
    ///
    /// NOTE: These effects are not necessarily compatible with
    /// [`TransactionEffects`]
    pub async fn execute_with_gas_station(
        mut self,
        signer: &impl TransactionSigner,
    ) -> Result<serde_json::Value, Error> {
        let gas_station_data = self.data.gas_station_data.take();

        Ok(if let Some(gas_station_data) = gas_station_data {
            let mut txn = self.finish()?;
            gas_station_data.execute_txn_json(&mut txn, signer).await?
        } else {
            return Err(Error::MissingGasStationData);
        })
    }
}

impl<C, L> TransactionBuilder<C, L> {
    /// Get the client used by the builder.
    pub fn get_client(&self) -> &C {
        &self.client
    }
}

impl<C: TransactionBuilderClient, L> TransactionBuilder<C, L> {
    /// Add gas coins that will be consumed. If no gas coins are provided, the
    /// client will set a default list owned by the sender.
    ///
    /// # Example
    ///
    /// ```
    /// # use iota_sdk_transaction_builder::TestClient;
    /// use std::str::FromStr;
    ///
    /// use iota_sdk_transaction_builder::{TransactionBuilder, assigned, unresolved};
    /// use iota_types::{Address, ObjectDigest, ObjectId, ObjectReference, Transaction};
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> eyre::Result<()> {
    /// # let client = TestClient;
    /// let sender =
    ///     Address::from_str("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")?;
    ///
    /// let mut builder = TransactionBuilder::new(sender).with_client(client);
    ///
    /// let gas_coin1 =
    ///     ObjectId::from_str("0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc")?;
    /// let gas_coin2 =
    ///     ObjectId::from_str("0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db")?;
    ///
    /// builder
    ///     .split_coins(unresolved::Argument::Gas, [1000u64])
    ///     .gas([gas_coin1, gas_coin2]);
    ///
    /// let txn: Transaction = builder.finish().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn gas(&mut self, obj_ids: impl IntoIterator<Item = ObjectId>) -> &mut Self {
        for id in obj_ids {
            self.set_input(InputKind::ImmutableOrOwned(id), true);
        }
        self
    }

    /// Add gas coins that will be consumed, by reference. Optional.
    ///
    /// Same as [`gas`](Self::gas), but for coins the caller has already
    /// resolved: the builder takes the references as given instead of looking
    /// the objects up. Setting either one stops the builder from picking gas
    /// coins on its own.
    ///
    /// # Example
    ///
    /// ```
    /// # use iota_sdk_transaction_builder::TestClient;
    /// use std::str::FromStr;
    ///
    /// use iota_sdk_transaction_builder::{TransactionBuilder, unresolved};
    /// use iota_types::{Address, ObjectDigest, ObjectId, ObjectReference, Transaction, Version};
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> eyre::Result<()> {
    /// # let client = TestClient;
    /// let sender =
    ///     Address::from_str("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")?;
    ///
    /// let mut builder = TransactionBuilder::new(sender).with_client(client);
    ///
    /// let gas_coin1 = ObjectReference {
    ///     object_id: ObjectId::from_str(
    ///         "0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc",
    ///     )?,
    ///     digest: ObjectDigest::from_str("CPpQZqyHZcG2Pb9gZyikbc8dEuyipXHR6ihnfe9iYiMt")?,
    ///     version: Version::from_u64(473053811),
    /// };
    /// let gas_coin2 = ObjectReference {
    ///     object_id: ObjectId::from_str(
    ///         "0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db",
    ///     )?,
    ///     digest: ObjectDigest::from_str("8ahH5RXFnK1jttQEWTypYX7MRzLuQDEXk7fhMHCyZekX")?,
    ///     version: Version::from_u64(473053810),
    /// };
    ///
    /// builder
    ///     .split_coins(unresolved::Argument::Gas, [1000u64])
    ///     .gas_refs([gas_coin1, gas_coin2])
    ///     .gas_budget(1000000000)
    ///     .gas_price(100);
    ///
    /// let txn: Transaction = builder.finish().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn gas_refs(&mut self, obj_refs: impl IntoIterator<Item = ObjectReference>) -> &mut Self {
        for obj_ref in obj_refs {
            self.set_input(
                InputKind::Input(iota_types::Input::ImmutableOrOwned(obj_ref)),
                true,
            );
        }
        self
    }

    /// Pick gas coins owned by the sponsor (or the sender) unless the caller
    /// already set some with [`gas`](Self::gas) or
    /// [`gas_refs`](Self::gas_refs).
    async fn select_default_gas(&mut self) -> Result<(), Error> {
        if !self.data.inputs.values().any(|i| i.is_gas) {
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
                    if let Argument::Input(idx) = arg
                        && let Some(obj_id) = self.data.inputs[idx].object_id()
                    {
                        unusable_object_ids.insert(*obj_id);
                    }
                }
            }
            // Auto gas selection: page through the owner's gas coins, keeping a
            // running top-K by balance (K = the protocol cap). Stop as soon as
            // the selected coins cover the requested budget, or the pages run
            // out; with no budget set, walk every page. This deliberately
            // over-includes — in the common case a wallet owns fewer coins than
            // the cap, so the whole set is pinned — and gas smashing during
            // execution consolidates the balances into a single coin.
            let max_gas_payment_objects = self
                .client
                .protocol_config()
                .await
                .ok()
                .and_then(|cfg| {
                    cfg.attributes
                        .get(MAX_GAS_PAYMENT_OBJECTS_KEY)
                        .and_then(|v| v.parse::<usize>().ok())
                })
                .and_then(|v| v.checked_sub(1))
                .unwrap_or(DEFAULT_MAX_GAS_PAYMENT_OBJECTS);
            let owner = self.data.sponsor.unwrap_or(self.data.sender);
            let target_budget = self.data.gas_budget;
            let mut selected: Vec<(u64, ObjectReference)> = Vec::new();
            let mut cursor: Option<Vec<u8>> = None;
            loop {
                let page = self
                    .client
                    .objects(Some(StructTag::new_gas_coin()), owner, cursor, None)
                    .await
                    .map_err(Error::client)?;
                for obj in page.data {
                    if unusable_object_ids.contains(&obj.id()) {
                        continue;
                    }
                    let Ok(coin) = Coin::try_from_object(&obj) else {
                        continue;
                    };
                    selected.push((coin.balance(), obj.object_ref()));
                }
                selected.sort_by_key(|c| std::cmp::Reverse(c.0));
                selected.truncate(max_gas_payment_objects);

                let covers_budget = target_budget.is_some_and(|budget| {
                    selected
                        .iter()
                        .map(|(b, _)| *b)
                        .fold(0u64, u64::saturating_add)
                        >= budget
                });
                if covers_budget || page.next_cursor.is_none() {
                    break;
                }
                cursor = page.next_cursor;
            }

            // Add all selected coins as gas inputs (without early break): the
            // extra balance gets consolidated by gas smashing during execution.
            for (_, obj_ref) in selected {
                self.set_input(
                    InputKind::Input(iota_types::Input::ImmutableOrOwned(obj_ref)),
                    true,
                );
            }
        }
        Ok(())
    }

    /// Fetch every object that `inputs` refers to by id, in a single request.
    ///
    /// Inputs are de-duplicated by object id, so each id is fetched once.
    async fn fetch_input_objects(
        &self,
        inputs: &[(InputId, Input)],
    ) -> Result<HashMap<ObjectId, Object>, Error> {
        let mut requests = Vec::new();
        for (_, input) in inputs {
            if let InputKind::ImmutableOrOwned(object_id)
            | InputKind::Receiving(object_id)
            | InputKind::Shared { object_id, .. } = &input.kind
            {
                requests.push((*object_id, None));
            }
        }
        if requests.is_empty() {
            return Ok(HashMap::new());
        }
        // Pairs answers with requests by position, which `objects_by_id` is
        // documented to allow. The client is responsible for holding the server
        // to that.
        let fetched = self
            .client
            .objects_by_id(&requests)
            .await
            .map_err(Error::client)?;
        requests
            .into_iter()
            .zip(fetched)
            .map(|((object_id, _), object)| {
                object
                    .map(|object| (object_id, object))
                    .ok_or_else(|| Error::Input(format!("missing object {object_id}")))
            })
            .collect()
    }

    /// Resolve the inputs and commands into a [`TransactionKind`], returning it
    /// together with the gas coins currently set on the builder.
    async fn resolve_kind(&mut self) -> Result<(TransactionKind, Vec<ObjectReference>), Error> {
        let taken_inputs: Vec<_> = std::mem::take(&mut self.data.inputs).into_iter().collect();
        let objects = self.fetch_input_objects(&taken_inputs).await?;
        let object = |object_id: ObjectId| {
            objects
                .get(&object_id)
                .ok_or_else(|| Error::Input(format!("missing object {object_id}")))
        };

        let mut inputs = Vec::new();
        let mut gas = Vec::new();
        let mut input_map = HashMap::new();
        for (id, input) in taken_inputs {
            match input.kind {
                InputKind::ImmutableOrOwned(object_id) | InputKind::Receiving(object_id) => {
                    let obj = object(object_id)?;

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
                            Owner::Shared(v) => iota_types::Input::Shared(SharedObjectReference {
                                object_id,
                                initial_shared_version: *v,
                                mutable: false,
                            }),
                            _ => unimplemented!(
                                "a new enum variant was added and needs to be handled"
                            ),
                        };
                        let idx = inputs.len();
                        inputs.push(input);
                        input_map.insert(id, idx as u16);
                    }
                }
                InputKind::Shared { object_id, mutable } => {
                    let obj = object(object_id)?;

                    let input = match obj.owner() {
                        Owner::Shared(version) => {
                            iota_types::Input::Shared(SharedObjectReference {
                                object_id,
                                initial_shared_version: *version,
                                mutable,
                            })
                        }
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
        let kind =
            iota_types::TransactionKind::Programmable(ProgrammableTransaction { inputs, commands });
        Ok((kind, gas))
    }

    async fn resolve_ptb(&mut self, default_gas: bool) -> Result<Transaction, Error> {
        if default_gas {
            self.select_default_gas().await?;
        }
        let (kind, gas) = self.resolve_kind().await?;
        let price = match self.data.gas_price {
            Some(price) => price,
            None => self
                .client
                .reference_gas_price(None)
                .await
                .map_err(Error::client)?
                .ok_or_else(|| Error::MissingGasPrice)?,
        };
        Ok(TransactionV1 {
            kind,
            sender: self.data.sender,
            gas_payment: GasPayment {
                objects: gas,
                owner: self.data.sponsor.unwrap_or(self.data.sender),
                price,
                budget: self.data.gas_budget.unwrap_or(0),
            },
            expiration: self.data.expiration,
        }
        .into())
    }

    async fn finish_internal(&mut self) -> Result<Transaction, Error> {
        let mut txn = self.resolve_ptb(true).await?;
        if self.data.gas_budget.is_none() {
            let budget = self
                .client
                .estimate_tx_budget(&txn)
                .await
                .map_err(Error::client)?
                .ok_or(Error::MissingGasBudget)?;
            let Transaction::V1(txn) = &mut txn else {
                unimplemented!("a new enum variant was added and needs to be handled")
            };
            // The network enforces a minimum gas budget of base_tx_cost_fixed
            // (1000) * gas_price. The dry-run estimate can return a value below
            // this minimum, so we clamp it.
            let min_budget = txn.gas_payment.price.saturating_mul(1000);
            txn.gas_payment.budget = budget.max(min_budget);
        }

        Ok(txn)
    }

    /// Convert this builder into a transaction.
    pub async fn finish(mut self) -> Result<Transaction, Error> {
        self.finish_internal().await
    }

    /// Convert this builder into a [`TransactionKind`], resolving the inputs
    /// with the client but leaving the gas alone.
    ///
    /// Use this when the gas payment is decided elsewhere — a wallet that picks
    /// the gas coins itself, or a caller that needs the kind to estimate a
    /// budget before it can pick them. Unlike [`finish`](Self::finish), no gas
    /// coins are selected, no budget is estimated and no gas price is fetched,
    /// so this costs nothing beyond resolving the inputs. Any gas set with
    /// [`gas`](Self::gas) or [`gas_refs`](Self::gas_refs), and the sponsor,
    /// price, budget and expiration, are not part of a
    /// [`TransactionKind`] and are dropped.
    ///
    /// # Example
    ///
    /// ```
    /// # use iota_sdk_transaction_builder::TestClient;
    /// use std::str::FromStr;
    ///
    /// use iota_sdk_transaction_builder::TransactionBuilder;
    /// use iota_types::{Address, ObjectId, TransactionKind};
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> eyre::Result<()> {
    /// # let client = TestClient;
    /// let sender =
    ///     Address::from_str("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")?;
    /// let to_address =
    ///     Address::from_str("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;
    /// let coin =
    ///     ObjectId::from_str("0xe0e45ecb12ddca5f0d5192d2ee9e7f711959aa98614f9905e1e25c612ffd99a2")?;
    ///
    /// let mut builder = TransactionBuilder::new(sender).with_client(client);
    /// builder.transfer_objects(to_address, [coin]);
    ///
    /// let kind: TransactionKind = builder.finish_kind().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn finish_kind(mut self) -> Result<TransactionKind, Error> {
        let (kind, _gas) = self.resolve_kind().await?;
        Ok(kind)
    }

    /// Dry run the transaction.
    pub async fn dry_run(mut self, skip_checks: bool) -> Result<C::DryRunResult, Error> {
        let txn = self.resolve_ptb(false).await?;
        {
            let Transaction::V1(txn) = &txn else {
                unimplemented!("a new enum variant was added and needs to be handled")
            };
            if !txn.gas_payment.objects.is_empty() && txn.gas_payment.budget == 0 {
                return Err(Error::DryRun(
                    "gas coins were provided without a gas budget".to_owned(),
                ));
            }
        }
        let res = self
            .client
            .dry_run_tx(&txn, skip_checks)
            .await
            .map_err(Error::client)?;
        Ok(res)
    }

    /// Execute the transaction and optionally wait for finalization. The
    /// client will be used unless a gas station was configured, in
    /// which case the transaction will be sent to the endpoint for execution.
    pub async fn execute(
        mut self,
        signer: &impl TransactionSigner,
        wait_for: impl Into<Option<WaitForTx>>,
    ) -> Result<TransactionEffects, Error> {
        let wait_for = wait_for.into();
        let gas_station_data = self.data.gas_station_data.take();
        let mut txn = self.finish_internal().await?;

        Ok(if let Some(gas_station_data) = gas_station_data {
            let digest = gas_station_data.execute_txn(&mut txn, signer).await?;
            self.client
                .wait_for_tx(digest, WaitForTx::Finalized)
                .await
                .map_err(Error::client)?;
            self.client
                .transaction_effects(digest)
                .await
                .map_err(Error::client)?
                .ok_or_else(|| Error::MissingTransaction(digest))?
        } else {
            self.client
                .execute_tx(
                    &[signer.sign(&txn).await.map_err(Error::signature)?],
                    &txn,
                    wait_for,
                )
                .await
                .map_err(Error::client)?
        })
    }

    /// Execute the transaction with a sponsor signer and optionally wait for
    /// finalization.
    pub async fn execute_with_sponsor(
        mut self,
        signer: &impl TransactionSigner,
        sponsor_signer: &impl TransactionSigner,
        wait_for: impl Into<Option<WaitForTx>>,
    ) -> Result<TransactionEffects, Error> {
        let wait_for = wait_for.into();
        let txn = self.finish_internal().await?;

        let signatures = vec![
            signer.sign(&txn).await.map_err(Error::signature)?,
            sponsor_signer.sign(&txn).await.map_err(Error::signature)?,
        ];

        self.client
            .execute_tx(&signatures, &txn, wait_for)
            .await
            .map_err(Error::client)
    }
}

impl<C> TransactionBuilder<C, MoveCall> {
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
    pub fn package_id(&mut self, name: impl AssignedResult) -> &mut TransactionBuilder {
        let cap = self.arg();
        self.move_call(Address::FRAMEWORK, "package", "upgrade_package")
            .arguments([cap])
            .assign(name)
            .reset()
    }
}

impl<C: TransactionBuilderClient> TransactionBuilder<C, Publish> {
    /// Get the package ID from the UpgradeCap so that it can be used for future
    /// commands.
    pub fn package_id(&mut self, name: impl AssignedResult) -> &mut TransactionBuilder<C> {
        let cap = self.arg();
        self.move_call(Address::FRAMEWORK, "package", "upgrade_package")
            .arguments([cap])
            .assign(name)
            .reset()
    }
}

impl<C> TransactionBuilder<C, Publish> {
    /// Finish the publish call and return the UpgradeCap.
    pub fn upgrade_cap(&mut self, name: impl AssignedResult) -> &mut TransactionBuilder<C> {
        name.push_assigned_results(&mut self.data);

        self.reset()
    }
}

impl<C, L: Into<Command>> TransactionBuilder<C, L> {
    /// Assign a name to the last command's result.
    pub fn assign(&mut self, name: impl AssignedResults) -> &mut Self {
        name.push_assigned_results(&mut self.data);
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

#[cfg(test)]
mod tests {
    use iota_types::{ObjectDigest, Version};

    use super::*;

    /// Verify that `TryFrom<Transaction>` preserves input ordering: non-gas
    /// inputs occupy `BTreeMap` keys `0..n` matching their original positions,
    /// gas inputs follow with keys `n..n+m`, and `Argument::Input(i)` indices
    /// in commands continue to point at the same input.
    #[test]
    fn try_from_preserves_input_indices() {
        let sender: Address = "0xc574ea804d9c1a27c886312e96c0e2c9cfd71923ebaeb3000d04b5e65fca2793"
            .parse()
            .unwrap();
        let object_ref = |seed: u8| {
            let mut id_bytes = [0u8; 32];
            id_bytes[0] = seed;
            ObjectReference::new(
                ObjectId::new(id_bytes),
                Version::from_u64(seed as u64 + 1),
                ObjectDigest::new([seed; 32]),
            )
        };

        // Three distinct inputs; commands deliberately reference them out of
        // order so a re-numbering bug would surface.
        let original_inputs = vec![
            iota_types::Input::Pure(bcs::to_bytes(&42u64).unwrap()),
            iota_types::Input::ImmutableOrOwned(object_ref(1)),
            iota_types::Input::Pure(bcs::to_bytes(&7u64).unwrap()),
        ];
        let original_commands = vec![iota_types::Command::SplitCoins(iota_types::SplitCoins {
            coin: iota_types::Argument::Input(1),
            amounts: vec![
                iota_types::Argument::Input(2),
                iota_types::Argument::Input(0),
            ],
        })];
        let gas_coins = vec![object_ref(98), object_ref(99)];

        let txn = Transaction::V1(TransactionV1 {
            kind: TransactionKind::Programmable(ProgrammableTransaction {
                inputs: original_inputs.clone(),
                commands: original_commands,
            }),
            sender,
            gas_payment: GasPayment {
                objects: gas_coins.clone(),
                owner: sender,
                price: 1000,
                budget: 5_000_000,
            },
            expiration: TransactionExpiration::None,
        });

        let rebuilt = TransactionBuilder::try_from(txn).unwrap();

        // Keys are 0..n+m in order; non-gas first, gas appended.
        let keys: Vec<_> = rebuilt.data.inputs.keys().copied().collect();
        let n = original_inputs.len();
        let m = gas_coins.len();
        assert_eq!(keys, (0..n + m).collect::<Vec<_>>());

        // Non-gas inputs at keys 0..n match the originals byte-for-byte.
        for (i, expected) in original_inputs.iter().enumerate() {
            let stored = &rebuilt.data.inputs[&i];
            assert!(!stored.is_gas, "input {i} should not be flagged as gas");
            let InputKind::Input(actual) = &stored.kind else {
                panic!("input {i}: expected InputKind::Input");
            };
            assert_eq!(actual, expected);
        }

        // Gas inputs at keys n..n+m are flagged is_gas and round-trip through
        // InputKind::Input(ImmutableOrOwned).
        for (offset, expected) in gas_coins.iter().enumerate() {
            let key = n + offset;
            let stored = &rebuilt.data.inputs[&key];
            assert!(stored.is_gas, "input {key} should be flagged as gas");
            let InputKind::Input(iota_types::Input::ImmutableOrOwned(actual)) = &stored.kind else {
                panic!("gas input {key}: expected ImmutableOrOwned");
            };
            assert_eq!(actual, expected);
        }

        // Argument::Input indices in commands are untouched.
        let Command::SplitCoins(split) = &rebuilt.data.commands[0] else {
            panic!("expected SplitCoins command");
        };
        assert!(matches!(split.coin, Argument::Input(1)));
        assert!(matches!(split.amounts[0], Argument::Input(2)));
        assert!(matches!(split.amounts[1], Argument::Input(0)));
    }

    #[cfg(feature = "test-client")]
    mod input_resolution {
        use iota_types::Version;

        use super::*;
        use crate::RecordingClient;

        fn object_id(seed: u8) -> ObjectId {
            ObjectId::new([seed; ObjectId::LENGTH])
        }

        /// Every object input is fetched in one batch, and none of them fall
        /// back to a single-object request.
        #[tokio::test]
        async fn all_inputs_are_fetched_in_one_request() {
            let sender = Address::generate(rand::thread_rng());
            let client = RecordingClient::default();

            let mut builder = TransactionBuilder::new(sender).with_client(client.clone());
            builder.transfer_objects(sender, [object_id(1), object_id(2), object_id(3)]);
            builder
                .move_call(Address::FRAMEWORK, "clock", "timestamp_ms")
                .arguments([crate::Shared(ObjectId::CLOCK)]);
            builder.gas_refs([ObjectReference::new(
                object_id(9),
                Version::from_u64(1),
                iota_types::ObjectDigest::new([9; 32]),
            )]);

            builder.finish_kind().await.unwrap();

            assert_eq!(
                client.batches(),
                vec![vec![
                    object_id(1),
                    object_id(2),
                    object_id(3),
                    ObjectId::CLOCK,
                ]],
                "expected a single batch holding every object input"
            );
            assert!(
                client.singles().is_empty(),
                "no input should need a single-object request"
            );
        }

        /// Batched objects are matched back to the input that asked for them,
        /// so the shared object keeps its shared kind.
        #[tokio::test]
        async fn batched_objects_are_matched_to_their_inputs() {
            let sender = Address::generate(rand::thread_rng());
            let coin = object_id(1);

            let mut builder =
                TransactionBuilder::new(sender).with_client(RecordingClient::default());
            builder
                .move_call(Address::FRAMEWORK, "clock", "timestamp_ms")
                .arguments((crate::Shared(ObjectId::CLOCK), coin));

            let TransactionKind::Programmable(ptb) = builder.finish_kind().await.unwrap() else {
                panic!("expected a programmable transaction");
            };
            let iota_types::Input::Shared(shared) = &ptb.inputs[0] else {
                panic!("expected the clock to resolve as a shared input");
            };
            assert_eq!(shared.object_id, ObjectId::CLOCK);
            let iota_types::Input::ImmutableOrOwned(owned) = &ptb.inputs[1] else {
                panic!("expected the coin to resolve as an owned input");
            };
            assert_eq!(owned.object_id, coin);
        }

        /// A missing object is still reported by its own id.
        #[tokio::test]
        async fn a_missing_object_is_named_in_the_error() {
            let sender = Address::generate(rand::thread_rng());
            let absent = object_id(2);
            let client = RecordingClient {
                missing: vec![absent],
                ..Default::default()
            };

            let mut builder = TransactionBuilder::new(sender).with_client(client);
            builder.transfer_objects(sender, [object_id(1), absent]);

            let err = builder.finish_kind().await.unwrap_err();
            assert!(
                err.to_string().contains(&absent.to_string()),
                "error should name the missing object, got: {err}"
            );
        }
    }

    #[cfg(feature = "test-client")]
    mod finish_kind {
        use iota_types::{ObjectDigest, Version};

        use super::super::*;
        use crate::TestClient;

        /// The gas coin id [`TestClient`] hands out to gas selection.
        const SELECTABLE_GAS_COIN: ObjectId = ObjectId::new([0xee; ObjectId::LENGTH]);

        fn object_ref(seed: u8, version: u64) -> ObjectReference {
            ObjectReference::new(
                ObjectId::new([seed; ObjectId::LENGTH]),
                Version::from_u64(version),
                ObjectDigest::new([seed; 32]),
            )
        }

        fn split_coin_arg(kind: &TransactionKind) -> iota_types::Argument {
            let TransactionKind::Programmable(ptb) = kind else {
                panic!("expected a programmable transaction");
            };
            let [iota_types::Command::SplitCoins(split)] = &ptb.commands[..] else {
                panic!("expected a single SplitCoins command");
            };
            split.coin
        }

        /// Automatic gas selection may claim a coin the caller named, which
        /// turns the command's `Argument::Input` into `Argument::Gas`.
        /// `finish_kind` selects no gas, so the command keeps pointing at the
        /// coin.
        #[tokio::test]
        async fn keeps_the_coin_that_gas_selection_would_claim() {
            let sender = Address::generate(rand::thread_rng());

            let mut builder = TransactionBuilder::new(sender).with_client(TestClient);
            builder.split_coins(SELECTABLE_GAS_COIN, [1_000u64]);
            let kind = builder.finish_kind().await.unwrap();
            assert_eq!(split_coin_arg(&kind), iota_types::Argument::Input(0));

            let mut builder = TransactionBuilder::new(sender).with_client(TestClient);
            builder.split_coins(SELECTABLE_GAS_COIN, [1_000u64]);
            builder.gas_budget(5_000_000).gas_price(1000);
            let Transaction::V1(txn) = builder.finish().await.unwrap() else {
                panic!("expected a V1 transaction");
            };
            assert_eq!(split_coin_arg(&txn.kind), iota_types::Argument::Gas);
        }

        /// Gas coins, sponsor, price, budget and expiration are not part of a
        /// [`TransactionKind`], so setting them makes no difference.
        #[tokio::test]
        async fn ignores_gas_and_transaction_metadata() {
            let sender = Address::generate(rand::thread_rng());
            let recipient = Address::generate(rand::thread_rng());
            let coin = ObjectId::new([7; ObjectId::LENGTH]);

            let mut plain = TransactionBuilder::new(sender).with_client(TestClient);
            plain.transfer_objects(recipient, [coin]);
            let expected = plain.finish_kind().await.unwrap();

            let mut decorated = TransactionBuilder::new(sender).with_client(TestClient);
            decorated.transfer_objects(recipient, [coin]);
            decorated
                .gas_refs([object_ref(99, 7)])
                .gas_budget(5_000_000)
                .gas_price(1000)
                .sponsor(Address::generate(rand::thread_rng()))
                .expiration(42);

            assert_eq!(decorated.finish_kind().await.unwrap(), expected);
        }

        /// `gas_refs` takes the references as given — no object lookup — and
        /// stops the builder from picking gas coins of its own.
        #[tokio::test]
        async fn gas_refs_are_used_as_given() {
            let sender = Address::generate(rand::thread_rng());
            // A version the test client never fabricates, so a lookup that
            // overwrote the reference would be visible.
            let gas_coin = object_ref(3, 4242);

            let mut builder = TransactionBuilder::new(sender).with_client(TestClient);
            builder.split_coins(Argument::Gas, [1_000u64]);
            builder
                .gas_refs([gas_coin])
                .gas_budget(5_000_000)
                .gas_price(1000);

            let Transaction::V1(txn) = builder.finish().await.unwrap() else {
                panic!("expected a V1 transaction");
            };
            assert_eq!(txn.gas_payment.objects, vec![gas_coin]);
        }
    }
}
