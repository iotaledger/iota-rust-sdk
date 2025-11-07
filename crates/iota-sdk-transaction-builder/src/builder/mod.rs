// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Builder for Programmable Transactions.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    marker::PhantomData,
    time::Duration,
};

use iota_crypto::{IotaSigner, simple::SimpleKeypair};
use iota_graphql_client::Client;
use iota_types::{
    Address, DryRunResult, GasPayment, Identifier, MovePackageData, ObjectId, ObjectReference,
    Owner, ProgrammableTransaction, StructTag, Transaction, TransactionEffects,
    TransactionExpiration, TransactionV1, TypeTag,
};
use reqwest::Url;
use serde::Serialize;

use crate::{
    ClientMethods, PTBArgument, SharedMut, WaitForTx,
    builder::{
        gas_station::GasStationData,
        named_results::{NamedResult, NamedResults},
        ptb_arguments::PTBArgumentList,
    },
    error::Error,
    types::{MoveType, MoveTypes},
    unresolved::{
        Argument, Command, Input, InputId, InputKind, MakeMoveVector, MergeCoins, MoveCall,
        Publish, SplitCoins, TransferObjects, Upgrade,
    },
};

pub(crate) mod client_methods;
pub(crate) mod gas_station;
mod named_results;
/// Argument types for PTBs
pub mod ptb_arguments;

const IOTA_SYSTEM_MODULE: &str = "iota_system";
const REQUEST_ADD_STAKE_FN: &str = "request_add_stake";
const REQUEST_WITHDRAW_STAKE_FN: &str = "request_withdraw_stake";

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
    pub fn get_named_result(&self, name: &str) -> Option<Argument> {
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
    pub fn with_client<C>(self, client: C) -> TransactionBuilder<C> {
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
        self.data.get_named_result(name)
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
    /// use std::str::FromStr;
    ///
    /// use iota_sdk_transaction_builder::{TransactionBuilder, res};
    /// use iota_types::{Address, Digest, ObjectId, ObjectReference, Transaction};
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> eyre::Result<()> {
    ///
    /// let client = iota_graphql_client::Client::new_devnet();
    /// let sender =
    ///     Address::from_str("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")?;
    ///
    /// let mut builder = TransactionBuilder::new(sender).with_client(client);
    ///
    /// # builder
    /// #     .split_coins(
    /// #         ObjectId::from_str(
    /// #             "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab",
    /// #         )?,
    /// #         [1000u64],
    /// #     )
    /// #     .name(("coin"));
    ///
    /// builder.transfer_objects(
    ///     Address::from_str("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?,
    ///     (
    ///         // ObjectIds can be passed when a client is provided
    ///         ObjectId::from_str(
    ///             "0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699",
    ///         )?,
    ///         // ObjectReferences are always allowed, though they must be correct
    ///         ObjectReference {
    ///             object_id: ObjectId::from_str(
    ///                 "0x8ef4259fa2a3499826fa4b8aebeb1d8e478cf5397d05361c96438940b43d28c9",
    ///             )?,
    ///             digest: Digest::from_str("4jJMQScR4z5kK3vchvDEFYTiCkZPEYdvttpi3iTj1gEW")?,
    ///             version: 435090179,
    ///         },
    ///         // The result of a previous command can also be used
    ///         res("coin"),
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
    /// ```rust
    /// use iota_graphql_client::Client;
    /// use iota_sdk_transaction_builder::TransactionBuilder;
    /// use iota_types::Address;
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> eyre::Result<()> {
    /// let client = Client::new_devnet();
    /// let from_address =
    ///     Address::from_hex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")?;
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
    /// ```rust
    /// use iota_graphql_client::Client;
    /// use iota_sdk_transaction_builder::TransactionBuilder;
    /// use iota_types::{Address, ObjectId};
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> eyre::Result<()> {
    /// let client = Client::new_devnet();
    /// let from_address =
    ///     Address::from_hex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")?;
    /// let to_address =
    ///     Address::from_hex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;
    ///
    /// // This is a coin of type
    /// // 0x3358bea865960fea2a1c6844b6fc365f662463dd1821f619838eb2e606a53b6a::cert::CERT
    /// let coin =
    ///     ObjectId::from_hex("0x8ef4259fa2a3499826fa4b8aebeb1d8e478cf5397d05361c96438940b43d28c9")?;
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
    /// ```rust
    /// use iota_graphql_client::Client;
    /// use iota_sdk_transaction_builder::TransactionBuilder;
    /// use iota_types::{Address, ObjectId};
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> eyre::Result<()> {
    /// let client = Client::new_devnet();
    /// let sender =
    ///     Address::from_hex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")?;
    ///
    /// let coin_0 =
    ///     ObjectId::from_hex("0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab")?;
    /// let coin_1 =
    ///     ObjectId::from_hex("0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699")?;
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
    /// ```rust
    /// use iota_graphql_client::Client;
    /// use iota_sdk_transaction_builder::{TransactionBuilder, res};
    /// use iota_types::{Address, ObjectId};
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> eyre::Result<()> {
    /// let client = Client::new_devnet();
    /// let sender =
    ///     Address::from_hex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")?;
    /// let coin =
    ///     ObjectId::from_hex("0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab")?;
    ///
    /// let mut builder = TransactionBuilder::new(sender).with_client(client);
    /// builder
    ///     .split_coins(coin, [1000u64, 2000, 3000])
    ///     .name(("coin1", "coin2", "coin3"))
    ///     .transfer_objects(sender, (res("coin1"), res("coin2"), res("coin3")));
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
    /// ```rust
    /// use iota_graphql_client::Client;
    /// use iota_sdk_transaction_builder::TransactionBuilder;
    /// use iota_types::{Address, ObjectId};
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> eyre::Result<()> {
    /// let client = Client::new_devnet();
    /// let sender =
    ///     Address::from_hex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")?;
    /// let validator_address = client
    ///     .active_validators(None, Default::default())
    ///     .await?
    ///     .data
    ///     .into_iter()
    ///     .next()
    ///     .ok_or_else(|| eyre::eyre!("no validators found"))?
    ///     .address
    ///     .address;
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
        self.move_call(Address::SYSTEM, IOTA_SYSTEM_MODULE, REQUEST_ADD_STAKE_FN)
            .arguments((SharedMut(ObjectId::SYSTEM), coin, validator_address))
            .state_change()
    }

    /// Withdraw stake from a validator's staking pool.
    ///
    /// # Example
    ///
    /// ```rust
    /// use iota_graphql_client::Client;
    /// use iota_sdk_transaction_builder::TransactionBuilder;
    /// use iota_types::{Address, ObjectId};
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> eyre::Result<()> {
    /// let client = Client::new_devnet();
    /// let sender =
    ///     Address::from_hex("0x6f0202b12cd398166bdd3716c9aa3f0b6218ba125491f7ea2bc660fdd5e57ff8")?;
    /// // This is a 0x3::staking_pool::StakedIota owned by the sender
    /// let staked_iota =
    ///     ObjectId::from_hex("0x00030af99878926cd11f8bdf4d2f67c4aa753a4afc249d776c8ed2cc88d7b8d5")?;
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
            IOTA_SYSTEM_MODULE,
            REQUEST_WITHDRAW_STAKE_FN,
        )
        .arguments((SharedMut(ObjectId::SYSTEM), staked_iota))
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
    /// use std::str::FromStr;
    ///
    /// use iota_sdk_transaction_builder::{TransactionBuilder, res};
    /// use iota_types::{Address, Transaction};
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> eyre::Result<()> {
    /// let client = iota_graphql_client::Client::new_devnet();
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
    ///     .name("addresses")
    ///     .move_call(Address::FRAMEWORK, "vec_map", "from_keys_values")
    ///     .generics::<(Address, u64)>()
    ///     .arguments((res("addresses"), [10000000u64, 20000000u64]));
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
    /// use iota_sdk_transaction_builder::{TransactionBuilder, res, unresolved};
    /// use iota_types::{Address, Digest, ObjectId, ObjectReference, Transaction};
    ///
    /// let sender =
    ///     Address::from_str("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")?;
    ///
    /// let mut builder = TransactionBuilder::new(sender);
    ///
    /// let gas_coin1 = ObjectReference {
    ///     object_id: ObjectId::from_str(
    ///         "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab",
    ///     )?,
    ///     digest: Digest::from_str("CPpQZqyHZcG2Pb9gZyikbc8dEuyipXHR6ihnfe9iYiMt")?,
    ///     version: 473053811,
    /// };
    /// let gas_coin2 = ObjectReference {
    ///     object_id: ObjectId::from_str(
    ///         "0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699",
    ///     )?,
    ///     digest: Digest::from_str("8ahH5RXFnK1jttQEWTypYX7MRzLuQDEXk7fhMHCyZekX")?,
    ///     version: 473053810,
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
        keypair: &SimpleKeypair,
    ) -> Result<serde_json::Value, Error> {
        let gas_station_data = self.data.gas_station_data.take();

        Ok(if let Some(gas_station_data) = gas_station_data {
            let mut txn = self.finish()?;
            gas_station_data.execute_txn_json(&mut txn, keypair).await?
        } else {
            return Err(Error::MissingGasStationData);
        })
    }
}

impl<L> TransactionBuilder<&Client, L> {
    /// Get the client used by the builder.
    pub fn get_client(&self) -> &Client {
        self.client
    }
}

impl<L> TransactionBuilder<Client, L> {
    /// Get the client used by the builder.
    pub fn get_client(&self) -> &Client {
        &self.client
    }
}

impl<C: ClientMethods, L> TransactionBuilder<C, L> {
    /// Add gas coins that will be consumed. If no gas coins are provided, the
    /// client will set a default list owned by the sender.
    ///
    /// # Example
    ///
    /// ```
    /// use std::str::FromStr;
    ///
    /// use iota_sdk_transaction_builder::{TransactionBuilder, res, unresolved};
    /// use iota_types::{Address, Digest, ObjectId, ObjectReference, Transaction};
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> eyre::Result<()> {
    /// let client = iota_graphql_client::Client::new_devnet();
    /// let sender =
    ///     Address::from_str("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")?;
    ///
    /// let mut builder = TransactionBuilder::new(sender).with_client(client);
    ///
    /// let gas_coin1 =
    ///     ObjectId::from_str("0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab")?;
    /// let gas_coin2 =
    ///     ObjectId::from_str("0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699")?;
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
                    Some(StructTag::new_gas_coin().into()),
                    Some(self.data.sponsor.unwrap_or(self.data.sender)),
                    None,
                    true,
                    None,
                    None,
                )
                .await
                .map_err(Error::client)?
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
                        .map_err(Error::client)?
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
                        .map_err(Error::client)?
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
                .map_err(Error::client)?
                .ok_or_else(|| Error::MissingGasPrice)?,
        };
        Ok(TransactionV1 {
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
            let Transaction::V1(txn) = &mut txn;
            txn.gas_payment.budget = budget
        }

        Ok(txn)
    }

    /// Convert this builder into a transaction.
    pub async fn finish(mut self) -> Result<Transaction, Error> {
        self.finish_internal().await
    }

    /// Dry run the transaction.
    pub async fn dry_run(mut self, skip_checks: bool) -> Result<DryRunResult, Error> {
        let txn = self.resolve_ptb(false).await?;
        {
            let Transaction::V1(txn) = &txn;
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
    /// GraphQL client will be used unless a gas station was configured, in
    /// which case the transaction will be sent to the endpoint for execution.
    pub async fn execute(
        mut self,
        keypair: &SimpleKeypair,
        wait_for: impl Into<Option<WaitForTx>>,
    ) -> Result<TransactionEffects, Error> {
        let wait_for = wait_for.into();
        let gas_station_data = self.data.gas_station_data.take();
        let mut txn = self.finish_internal().await?;

        Ok(if let Some(gas_station_data) = gas_station_data {
            let digest = gas_station_data.execute_txn(&mut txn, keypair).await?;
            if let Some(wait_for) = wait_for {
                self.client
                    .wait_for_tx(digest, wait_for)
                    .await
                    .map_err(Error::client)?;
            }
            self.client
                .transaction_effects(digest)
                .await
                .map_err(Error::client)?
                .ok_or_else(|| Error::MissingTransaction(digest))?
        } else {
            self.client
                .execute_tx(
                    &[keypair.sign_transaction(&txn).map_err(Error::Signature)?],
                    &txn,
                    wait_for,
                )
                .await
                .map_err(Error::client)?
        })
    }

    /// Execute the transaction with a sponsor keypair and optionally wait for
    /// finalization.
    pub async fn execute_with_sponsor(
        mut self,
        keypair: &SimpleKeypair,
        sponsor_keypair: &SimpleKeypair,
        wait_for: impl Into<Option<WaitForTx>>,
    ) -> Result<TransactionEffects, Error> {
        let wait_for = wait_for.into();
        let txn = self.finish_internal().await?;

        let mut signatures = vec![keypair.sign_transaction(&txn).map_err(Error::Signature)?];
        signatures.push(
            sponsor_keypair
                .sign_transaction(&txn)
                .map_err(Error::Signature)?,
        );

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
    pub fn package_id(&mut self, name: impl NamedResult) -> &mut TransactionBuilder {
        let cap = self.arg();
        self.move_call(Address::FRAMEWORK, "package", "upgrade_package")
            .arguments([cap])
            .name(name)
            .reset()
    }
}

impl<C: ClientMethods> TransactionBuilder<C, Publish> {
    /// Get the package ID from the UpgradeCap so that it can be used for future
    /// commands.
    pub fn package_id(&mut self, name: impl NamedResult) -> &mut TransactionBuilder<C> {
        let cap = self.arg();
        self.move_call(Address::FRAMEWORK, "package", "upgrade_package")
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
