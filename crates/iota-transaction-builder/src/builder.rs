// Copyright 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Builder for Programmable Transactions.

use core::marker::PhantomData;
use std::{collections::HashMap, future::Future};

use iota_crypto::IotaSigner;
use iota_graphql_client::Client;
use iota_types::{
    Address, Argument, Command, GasPayment, Identifier, IdentifierRef, Input, MakeMoveVector,
    MergeCoins, MoveCall, ObjectId, ObjectReference, Owner, Publish, SplitCoins, Transaction,
    TransactionEffects, TransactionExpiration, TransferObjects, Upgrade,
};
use serde::Serialize;

use crate::{
    error::Error,
    publish_type::PublishType,
    types::{MoveParam, MoveType, MoveTypes, ParamType},
};

/// A builder for a programmable transaction which provides a better API vs.
/// IOTAs [`ProgrammableTransactionBuilder`](IotaPTB).
///
/// Additional Features:
/// - Command results can be bound by a static name, and referenced by later
///   calls with that name using [`Res`].
/// - Parameters can be passed in without fiddling with inputs, and will be
///   automatically handled.
/// - Mixed parameters (new inputs and named references) can be defined in a
///   single tuple.
/// - The builder is 100% chainable, start-to-finish.
#[derive(Debug, Clone)]
pub struct TransactionBuilder<C> {
    /// The inputs to the transaction.
    inputs: Vec<Input>,
    /// The list of commands in the transaction. A command is a single operation
    /// in a programmable transaction.
    commands: Vec<Command>,
    /// The gas objects that will be used to pay for the transaction. The most
    /// common way is to use [`Input::owned`] function to create
    /// a gas object and use the [`add_gas_objects`](Self::add_gas_objects)
    /// method to set the gas objects.
    pub(crate) gas: Vec<ObjectReference>,
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
    named_commands: HashMap<&'static str, Argument>,
    client: C,
}

impl TransactionBuilder<()> {
    /// Instantiate a new PTB.
    pub fn new(sender: Address) -> TransactionBuilder<()> {
        TransactionBuilder {
            inputs: Default::default(),
            commands: Default::default(),
            gas: Default::default(),
            gas_budget: Default::default(),
            gas_price: Default::default(),
            sender,
            sponsor: Default::default(),
            expiration: Default::default(),
            named_commands: Default::default(),
            client: (),
        }
    }
}

impl<C> TransactionBuilder<C> {
    /// Set the client to enable automatic object resolution.
    pub fn with_client(self, client: Client) -> TransactionBuilder<Client> {
        TransactionBuilder {
            inputs: self.inputs,
            commands: self.commands,
            gas: self.gas,
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
    pub async fn transfer_iota(
        &mut self,
        recipient: Address,
        amount: impl Into<Option<u64>> + Send,
    ) -> Result<&mut Self, Error> {
        let rec_arg = self.pure(recipient)?;
        let coin_arg = if let Some(amount) = amount.into() {
            let amt_arg = self.pure(amount)?;
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
        Ok(self)
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

    /// Set the gas coins that will be consumed with all object reference data.
    /// Optional.
    pub async fn gas_ref(&mut self, obj_ref: ObjectReference) -> Result<&mut Self, Error> {
        self.gas.push(obj_ref);
        Ok(self)
    }

    /// Make a value available to the transaction as an input.
    pub fn input(&mut self, i: Input) -> Argument {
        let input = i.into();
        if let Some(i) = self.inputs.iter().position(|i| i == &input) {
            return Argument::Input(i as _);
        }
        self.inputs.push(input);
        Argument::Input((self.inputs.len() - 1) as _)
    }

    /// Add a pure input using the BCS serialized bytes
    pub fn pure_bytes(&mut self, bytes: Vec<u8>) -> Argument {
        self.input(Input::Pure { value: bytes })
    }

    /// Add a pure input
    pub fn pure<T: Serialize>(&mut self, value: T) -> Result<Argument, Error> {
        Ok(self.pure_bytes(bcs::to_bytes(&value).map_err(Error::Bcs)?))
    }

    /// Add a new command to the PTB
    pub fn command(&mut self, command: Command) -> Argument {
        let i = self.commands.len();
        self.commands.push(command);
        Argument::Result(i as u16)
    }
}

impl TransactionBuilder<()> {
    /// Set the gas coins that will be consumed. Optional.
    pub async fn gas(&mut self, obj_ref: ObjectReference) -> Result<&mut Self, Error> {
        self.gas.push(obj_ref);
        Ok(self)
    }

    /// Begin building a move call.
    pub fn move_call(
        &mut self,
        package_id: ObjectId,
        module: &'static str,
        function: &'static str,
    ) -> MoveCallCommandBuilder<'_, (), (), Vec<Input>> {
        MoveCallCommandBuilder::<(), (), Vec<Input>>::new(self, package_id, module, function)
    }

    /// Merge multiple coins into one.
    pub async fn merge_coins(
        &mut self,
        primary_coin: ObjectReference,
        consumed_coins: impl IntoIterator<Item = ObjectReference> + Send,
    ) -> Result<&mut Self, Error> {
        let primary_coin = self.input(Input::ImmutableOrOwned(primary_coin));
        let mut consumed = Vec::new();
        for coin in consumed_coins {
            consumed.push(self.input(Input::ImmutableOrOwned(coin)));
        }
        self.command(Command::MergeCoins(MergeCoins {
            coin: primary_coin,
            coins_to_merge: consumed,
        }));
        Ok(self)
    }

    /// Split a coin into many.
    pub async fn split_coins(
        &mut self,
        coin: ObjectReference,
        split_amounts: impl IntoIterator<Item = u64> + Send,
        name: impl NamedCommands,
    ) -> Result<&mut Self, Error> {
        let coin = if self
            .gas
            .iter()
            .find(|g| g.object_id() == coin.object_id())
            .is_some()
        {
            Argument::Gas
        } else {
            self.input(Input::ImmutableOrOwned(coin))
        };
        let split_amounts = split_amounts
            .into_iter()
            .map(|v| self.pure(v))
            .collect::<Result<_, _>>()?;
        self.command(Command::SplitCoins(SplitCoins {
            coin,
            amounts: split_amounts,
        }));
        name.push_named_commands(self);
        Ok(self)
    }

    /// Transfer objects to a recipient address.
    pub async fn transfer_objects(
        &mut self,
        recipient: Address,
        objects: impl IntoIterator<Item = ObjectReference>,
    ) -> Result<&mut Self, Error> {
        let objects = objects
            .into_iter()
            .map(|o| self.input(Input::ImmutableOrOwned(o)))
            .collect();
        let cmd = Command::TransferObjects(TransferObjects {
            objects,
            address: self.pure(recipient)?,
        });
        self.commands.push(cmd);
        Ok(self)
    }

    /// Convert this builder into a transaction.
    pub async fn finish(self) -> Result<Transaction, Error> {
        let Some(price) = self.gas_price else {
            return Err(Error::MissingGasPrice);
        };
        let Some(budget) = self.gas_budget else {
            return Err(Error::MissingGasBudget);
        };
        Ok(Transaction {
            kind: iota_types::TransactionKind::ProgrammableTransaction(
                iota_types::ProgrammableTransaction {
                    inputs: self.inputs,
                    commands: self.commands,
                },
            ),
            sender: self.sender,
            gas_payment: {
                GasPayment {
                    objects: self.gas,
                    owner: self.sponsor.unwrap_or(self.sender),
                    price,
                    budget,
                }
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
    pub async fn gas(&mut self, object_id: ObjectId) -> Result<&mut Self, Error> {
        let obj = self
            .client
            .object(object_id, None)
            .await
            .map_err(Error::Client)?
            .ok_or_else(|| Error::Input(format!("missing object {object_id}")))?;

        let obj_ref = match obj.owner() {
            Owner::Address(_) | Owner::Object(_) | Owner::Immutable => {
                ObjectReference::new(object_id, obj.version(), obj.digest())
            }
            Owner::Shared(_) => return Err(Error::WrongGasObject),
        };

        self.gas.push(obj_ref);
        Ok(self)
    }

    /// Begin building a move call.
    pub fn move_call(
        &mut self,
        package_id: ObjectId,
        module: &'static str,
        function: &'static str,
    ) -> MoveCallCommandBuilder<'_, Client> {
        MoveCallCommandBuilder::<Client>::new(self, package_id, module, function)
    }

    /// Transfer objects to a recipient address.
    pub async fn transfer_objects<U: PTBArguments>(
        &mut self,
        recipient: Address,
        objects: U,
    ) -> Result<&mut Self, Error> {
        let objects = objects
            .args(self)
            .await
            .map_err(|e| Error::Input(e.to_string()))?;
        let cmd = Command::TransferObjects(TransferObjects {
            objects,
            address: self.pure(recipient)?,
        });
        self.commands.push(cmd);
        Ok(self)
    }

    /// Merge multiple coins into one.
    pub async fn merge_coins(
        &mut self,
        primary_coin: ObjectId,
        consumed_coins: impl IntoIterator<Item = ObjectId> + Send,
    ) -> Result<&mut Self, Error> {
        let primary_coin = self.resolve_obj(primary_coin, true, false).await?;
        let mut consumed = Vec::new();
        for coin in consumed_coins {
            consumed.push(self.resolve_obj(coin, true, false).await?);
        }
        self.command(Command::MergeCoins(MergeCoins {
            coin: primary_coin,
            coins_to_merge: consumed,
        }));
        Ok(self)
    }

    /// Split a coin into many.
    pub async fn split_coins(
        &mut self,
        coin: ObjectId,
        split_amounts: impl IntoIterator<Item = u64> + Send,
        name: impl NamedCommands,
    ) -> Result<&mut Self, Error> {
        let coin = if self.gas.iter().find(|g| g.object_id() == &coin).is_some() {
            Argument::Gas
        } else {
            self.resolve_obj(coin, true, false).await?
        };
        let split_amounts = split_amounts
            .into_iter()
            .map(|v| self.pure(v))
            .collect::<Result<_, _>>()?;
        self.command(Command::SplitCoins(SplitCoins {
            coin,
            amounts: split_amounts,
        }));
        name.push_named_commands(self);
        Ok(self)
    }

    /// Publish a move package. Returns the upgrade capability, if there is one.
    pub fn publish(
        &mut self,
        kind: impl Into<PublishType> + Send,
    ) -> Result<PublishBuilder<'_>, Error> {
        PublishBuilder::new(self, kind)
    }

    /// Upgrade a move package.
    pub async fn upgrade<U: PTBArguments>(
        &mut self,
        package_id: ObjectId,
        upgrade_cap: U,
        kind: impl Into<PublishType> + Send,
        name: impl NamedCommands,
    ) -> Result<&mut Self, Error> {
        let module = match kind.into() {
            PublishType::Path(_path) => todo!("load the package from the path"),
            PublishType::Compiled(m) => m,
        };
        let ticket = upgrade_cap
            .args(self)
            .await
            .map_err(|e| Error::Input(e.to_string()))?;
        if ticket.len() != 1 {
            return Err(Error::Input("invalid upgrade cap".to_owned()));
        }
        self.command(Command::Upgrade(Upgrade {
            modules: module.modules,
            dependencies: module.dependencies,
            package: package_id,
            ticket: ticket.into_iter().next().unwrap(),
        }));
        name.push_named_commands(self);
        Ok(self)
    }

    /// Make a move vector from a list of elements.
    pub async fn make_move_vec<U: PTBArguments + MoveType>(
        &mut self,
        elements: impl IntoIterator<Item = U> + Send,
        name: impl NamedCommands,
    ) -> Result<&mut Self, Error> {
        let mut args = Vec::new();
        for e in elements {
            args.extend(
                e.args(self)
                    .await
                    .map_err(|e| Error::Input(e.to_string()))?,
            );
        }
        let cmd = Command::MakeMoveVector(MakeMoveVector {
            type_: Some(U::type_tag()),
            elements: args,
        });
        self.commands.push(cmd);
        name.push_named_commands(self);
        Ok(self)
    }

    async fn resolve_obj(
        &mut self,
        object_id: ObjectId,
        mutable: bool,
        receiving: bool,
    ) -> Result<Argument, Error> {
        let obj = self
            .client
            .object(object_id, None)
            .await
            .map_err(Error::Client)?
            .ok_or_else(|| Error::Input(format!("missing object {object_id}")))?;

        Ok(match obj.owner() {
            Owner::Address(_) | Owner::Object(_) | Owner::Immutable => {
                let obj_ref = ObjectReference::new(object_id, obj.version(), obj.digest());
                if receiving {
                    self.input(Input::Receiving(obj_ref))
                } else {
                    self.input(Input::ImmutableOrOwned(obj_ref))
                }
            }
            Owner::Shared(version) => self.input(Input::Shared {
                object_id,
                initial_shared_version: *version,
                mutable,
            }),
        })
    }

    /// Convert this builder into a transaction.
    pub async fn finish(self) -> Result<Transaction, Error> {
        let price = match self.gas_price {
            Some(price) => price,
            None => self
                .client
                .reference_gas_price(None)
                .await
                .map_err(Error::Client)?
                .ok_or_else(|| Error::MissingGasPrice)?,
        };
        let mut txn = Transaction {
            kind: iota_types::TransactionKind::ProgrammableTransaction(
                iota_types::ProgrammableTransaction {
                    inputs: self.inputs,
                    commands: self.commands,
                },
            ),
            sender: self.sender,
            gas_payment: {
                GasPayment {
                    objects: self.gas,
                    owner: self.sponsor.unwrap_or(self.sender),
                    price,
                    budget: 0,
                }
            },
            expiration: self.expiration,
        };
        println!("{txn:#?}");
        txn.gas_payment.budget = match self.gas_budget {
            Some(budget) => budget,
            None => {
                let res = self
                    .client
                    .dry_run_tx(&txn, true)
                    .await
                    .map_err(Error::Client)?;
                res.effects
                    .ok_or_else(|| Error::MissingGasBudget)?
                    .gas_summary()
                    .gas_used()
            }
        };

        Ok(txn)
    }

    /// Execute the publish with the given data.
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

/// A builder for a move call command within a programmable transaction.
#[derive(Debug)]
pub struct MoveCallCommandBuilder<'a, C, G: MoveTypes = (), A = ()> {
    package: ObjectId,
    module: Identifier,
    function: Identifier,
    args: Option<A>,
    generics: PhantomData<G>,
    ptb: &'a mut TransactionBuilder<C>,
}

impl<'a, G: MoveTypes, A: PTBArguments> MoveCallCommandBuilder<'a, Client, G, A> {
    /// Instantiate a move call command builder.
    pub fn new(
        ptb: &'a mut TransactionBuilder<Client>,
        package_id: ObjectId,
        module: &'static str,
        function: &'static str,
    ) -> Self {
        Self {
            package: package_id,
            module: IdentifierRef::const_new(module).into(),
            function: IdentifierRef::const_new(function).into(),
            args: None,
            generics: PhantomData,
            ptb,
        }
    }

    /// Set the call params. Optional.
    pub fn params<U: PTBArguments>(self, params: U) -> MoveCallCommandBuilder<'a, Client, G, U> {
        MoveCallCommandBuilder {
            package: self.package,
            module: self.module,
            function: self.function,
            args: Some(params),
            generics: self.generics,
            ptb: self.ptb,
        }
    }

    /// Set the generic type arguments. Optional.
    pub fn generics<U: MoveTypes>(self) -> MoveCallCommandBuilder<'a, Client, U, A> {
        MoveCallCommandBuilder {
            package: self.package,
            module: self.module,
            function: self.function,
            args: self.args,
            generics: PhantomData,
            ptb: self.ptb,
        }
    }

    /// Finish the move call and return the PTB.
    pub async fn finish(self) -> Result<&'a mut TransactionBuilder<Client>, Error> {
        let args = if let Some(a) = self.args {
            a.args(self.ptb)
                .await
                .map_err(|e| Error::Input(e.to_string()))?
        } else {
            Vec::new()
        };

        self.ptb.command(Command::MoveCall(MoveCall {
            package: self.package,
            module: self.module,
            function: self.function,
            type_arguments: G::type_tags(),
            arguments: args,
        }));

        Ok(self.ptb)
    }

    /// Finish the move call by naming the output and return the PTB.
    pub async fn result(
        self,
        name: impl NamedCommands,
    ) -> Result<&'a mut TransactionBuilder<Client>, Error> {
        let ptb = self.finish().await?;

        name.push_named_commands(ptb);

        Ok(ptb)
    }
}

impl<'a, G: MoveTypes> MoveCallCommandBuilder<'a, (), G, Vec<Input>> {
    /// Instantiate a move call command builder.
    pub fn new(
        ptb: &'a mut TransactionBuilder<()>,
        package_id: ObjectId,
        module: &'static str,
        function: &'static str,
    ) -> Self {
        Self {
            package: package_id,
            module: IdentifierRef::const_new(module).into(),
            function: IdentifierRef::const_new(function).into(),
            args: None,
            generics: PhantomData,
            ptb,
        }
    }

    /// Set the call params. Optional.
    pub fn params(
        self,
        params: impl IntoIterator<Item = ObjectReference>,
    ) -> MoveCallCommandBuilder<'a, (), G, Vec<Input>> {
        MoveCallCommandBuilder {
            package: self.package,
            module: self.module,
            function: self.function,
            args: Some(
                params
                    .into_iter()
                    .map(|o| Input::ImmutableOrOwned(o))
                    .collect::<Vec<_>>(),
            ),
            generics: self.generics,
            ptb: self.ptb,
        }
    }

    /// Set the generic type arguments. Optional.
    pub fn generics<U: MoveTypes>(self) -> MoveCallCommandBuilder<'a, (), U, Vec<Input>> {
        MoveCallCommandBuilder {
            package: self.package,
            module: self.module,
            function: self.function,
            args: self.args,
            generics: PhantomData,
            ptb: self.ptb,
        }
    }

    /// Finish the move call and return the PTB.
    pub async fn finish(self) -> Result<&'a mut TransactionBuilder<()>, Error> {
        let args = if let Some(a) = self.args {
            a.into_iter().map(|i| self.ptb.input(i)).collect()
        } else {
            Vec::new()
        };

        self.ptb.command(Command::MoveCall(MoveCall {
            package: self.package,
            module: self.module,
            function: self.function,
            type_arguments: G::type_tags(),
            arguments: args,
        }));

        Ok(self.ptb)
    }

    /// Finish the move call by naming the output and return the PTB.
    pub async fn result(
        self,
        name: impl NamedCommands,
    ) -> Result<&'a mut TransactionBuilder<()>, Error> {
        let ptb = self.finish().await?;

        name.push_named_commands(ptb);

        Ok(ptb)
    }
}

/// A builder for a move call command within a programmable transaction.
#[derive(Debug)]
pub struct PublishBuilder<'a> {
    ptb: &'a mut TransactionBuilder<Client>,
    cap: Argument,
}

impl<'a> PublishBuilder<'a> {
    /// Instantiate a publish call builder.
    pub fn new(
        ptb: &'a mut TransactionBuilder<Client>,
        kind: impl Into<PublishType>,
    ) -> Result<Self, Error> {
        let module = match kind.into() {
            PublishType::Path(_path) => todo!("load the package from the path"),
            PublishType::Compiled(m) => m,
        };
        let cap = ptb.command(Command::Publish(Publish {
            modules: module.modules,
            dependencies: module.dependencies,
        }));
        Ok(Self { ptb, cap })
    }

    /// Get the package ID from the UpgradeCap so that it can be used for future
    /// commands.
    ///
    /// **NOTE:** This is currently not usable for move calls because the IOTA
    /// PTB does not support using an argument for the package ID.
    pub async fn package_id(
        self,
        name: impl NamedCommand,
    ) -> Result<&'a mut TransactionBuilder<Client>, Error> {
        self.ptb
            .move_call(Address::TWO.into(), "package", "upgrade_package")
            .params(self.cap)
            .result(name)
            .await?;
        Ok(self.ptb)
    }

    /// Finish the move call and return the UpgradeCap.
    pub fn upgrade_cap(
        self,
        name: impl NamedCommand,
    ) -> Result<&'a mut TransactionBuilder<Client>, Error> {
        name.push_named_commands(self.ptb);

        Ok(self.ptb)
    }
}

/// A trait which defines arguments for a [`TransactionBuilder`].
pub trait PTBArguments: Send + Sync {
    /// Get the arguments.
    fn args(
        &self,
        ptb: &mut TransactionBuilder<Client>,
    ) -> impl Future<Output = anyhow::Result<Vec<Argument>>> + Send {
        async {
            let mut args = Vec::new();
            self.push_args(ptb, &mut args).await?;
            Ok(args)
        }
    }

    /// Push the args onto the list.
    fn push_args(
        &self,
        ptb: &mut TransactionBuilder<Client>,
        args: &mut Vec<Argument>,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
}

macro_rules! impl_ptb_args_tuple {
    ($($tup:ident.$idx:tt),+$(,)?) => {
        impl<$($tup),+> PTBArguments for ($($tup),+)
        where $($tup: PTBArguments),+
        {
            async fn push_args(&self, ptb: &mut TransactionBuilder<Client>, args: &mut Vec<Argument>) -> anyhow::Result<()> {
                $(
                    self.$idx.push_args(ptb, args).await?;
                )+
                Ok(())
            }
        }
    };
}
impl_ptb_args_tuple!(T1.0, T2.1);
impl_ptb_args_tuple!(T1.0, T2.1, T3.2);
impl_ptb_args_tuple!(T1.0, T2.1, T3.2, T4.3);
impl_ptb_args_tuple!(T1.0, T2.1, T3.2, T4.3, T5.4);

impl<T: MoveParam + Send + Sync> PTBArguments for T {
    async fn push_args(
        &self,
        ptb: &mut TransactionBuilder<Client>,
        args: &mut Vec<Argument>,
    ) -> anyhow::Result<()> {
        let arg = match self.param()? {
            ParamType::Object(id) => ptb.resolve_obj(id, false, false).await?,
            ParamType::Pure(v) => ptb.pure_bytes(v),
        };
        args.push(arg);
        Ok(())
    }
}

impl PTBArguments for Argument {
    async fn push_args(
        &self,
        _: &mut TransactionBuilder<Client>,
        args: &mut Vec<Argument>,
    ) -> anyhow::Result<()> {
        args.push(*self);
        Ok(())
    }
}

/// Allows specifying mutable parameters.
pub struct Mut<T>(pub T);

impl<T: MoveParam + Send + Sync> PTBArguments for Mut<T> {
    async fn push_args(
        &self,
        ptb: &mut TransactionBuilder<Client>,
        args: &mut Vec<Argument>,
    ) -> anyhow::Result<()> {
        let arg = match self.0.param()? {
            ParamType::Object(id) => ptb.resolve_obj(id, true, false).await?,
            ParamType::Pure(v) => ptb.pure_bytes(v),
        };
        args.push(arg);
        Ok(())
    }
}

/// Allows specifying receiving parameters.
pub struct Receiving<T>(pub T);

impl<T: MoveParam + Send + Sync> PTBArguments for Receiving<T> {
    async fn push_args(
        &self,
        ptb: &mut TransactionBuilder<Client>,
        args: &mut Vec<Argument>,
    ) -> anyhow::Result<()> {
        let arg = match self.0.param()? {
            ParamType::Object(id) => ptb.resolve_obj(id, false, true).await?,
            ParamType::Pure(v) => ptb.pure_bytes(v),
        };
        args.push(arg);
        Ok(())
    }
}

/// The result of a previous command by name.
pub struct Res(pub &'static str);

impl PTBArguments for Res {
    async fn push_args(
        &self,
        ptb: &mut TransactionBuilder<Client>,
        args: &mut Vec<Argument>,
    ) -> anyhow::Result<()> {
        if let Some(arg) = ptb.named_commands.get(self.0) {
            args.push(*arg);
        } else {
            anyhow::bail!("no command named `{}` exists", self.0)
        }
        Ok(())
    }
}

/// A trait that defines a named command, either a string or nothing.
pub trait NamedCommand {
    /// Get the named command argument.
    fn named_command<C>(&self, ptb: &mut TransactionBuilder<C>) -> Argument;

    /// Push the named command to the PTB.
    fn push_named_command<C>(self, arg: Argument, ptb: &mut TransactionBuilder<C>);
}

impl NamedCommand for &'static str {
    fn named_command<C>(&self, ptb: &mut TransactionBuilder<C>) -> Argument {
        Argument::Result((ptb.commands.len() - 1) as _)
    }

    fn push_named_command<C>(self, arg: Argument, ptb: &mut TransactionBuilder<C>) {
        ptb.named_commands.insert(self, arg);
    }
}

impl NamedCommand for Option<&'static str> {
    fn named_command<C>(&self, ptb: &mut TransactionBuilder<C>) -> Argument {
        Argument::Result((ptb.commands.len() - 1) as _)
    }

    fn push_named_command<C>(self, arg: Argument, ptb: &mut TransactionBuilder<C>) {
        if let Some(s) = self {
            s.push_named_command(arg, ptb)
        }
    }
}

/// A trait that allows tuples to be used to bind nested named commands.
pub trait NamedCommands {
    /// Push the named commands to the PTB.
    fn push_named_commands<C>(self, ptb: &mut TransactionBuilder<C>);
}

impl<T: NamedCommand> NamedCommands for T {
    fn push_named_commands<C>(self, ptb: &mut TransactionBuilder<C>) {
        let arg = Argument::Result((ptb.commands.len() - 1) as _);
        self.push_named_command(arg, ptb)
    }
}

macro_rules! impl_named_command_tuple {
    ($($tup:ident.$idx:tt),+$(,)?) => {
        impl<$($tup),+> NamedCommands for ($($tup),+)
        where $($tup: NamedCommand),+
        {
            fn push_named_commands<C>(self, ptb: &mut TransactionBuilder<C>) {
                $(
                    let arg = Argument::NestedResult((ptb.commands.len() - 1) as _, $idx);
                    self.$idx.push_named_command(arg, ptb);
                )+
            }
        }
    };
}
impl_named_command_tuple!(T1.0, T2.1);
impl_named_command_tuple!(T1.0, T2.1, T3.2);
impl_named_command_tuple!(T1.0, T2.1, T3.2, T4.3);
impl_named_command_tuple!(T1.0, T2.1, T3.2, T4.3, T5.4);
impl_named_command_tuple!(T1.0, T2.1, T3.2, T4.3, T5.4, T6.5);

impl NamedCommands for () {
    fn push_named_commands<C>(self, _: &mut TransactionBuilder<C>) {}
}
