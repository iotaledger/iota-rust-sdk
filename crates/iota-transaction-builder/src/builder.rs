// Copyright 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Builder for Programmable Transactions.

use core::marker::PhantomData;
use std::collections::HashMap;

use iota_crypto::IotaSigner;
use iota_graphql_client::{Client, DryRunResult};
use iota_types::{
    Address, Argument, Command, GasPayment, Identifier, Input, MakeMoveVector, MergeCoins,
    MoveCall, ObjectId, ObjectReference, Owner, Publish, SplitCoins, Transaction,
    TransactionEffects, TransactionExpiration, TransferObjects, TypeTag, Upgrade,
};
use serde::Serialize;

use crate::{
    error::Error,
    publish_type::PublishType,
    types::{MoveParam, MoveType, MoveTypes, ParamType},
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum UnresolvedInput {
    /// A move object that is either immutable or address owned
    ImmutableOrOwned(ObjectId),
    /// A move object whose owner is "Shared"
    Shared {
        object_id: ObjectId,
        /// Controls whether the caller asks for a mutable reference to the
        /// shared object.
        mutable: bool,
    },
    /// A move object that is attempted to be received in this transaction.
    Receiving(ObjectId),
    Resolved(Input),
}

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
    inputs: Vec<UnresolvedInput>,
    /// The list of commands in the transaction. A command is a single operation
    /// in a programmable transaction.
    commands: Vec<Command>,
    /// The gas objects that will be used to pay for the transaction. The most
    /// common way is to use [`Input::owned`] function to create
    /// a gas object and use the [`add_gas_objects`](Self::add_gas_objects)
    /// method to set the gas objects.
    pub(crate) gas: Vec<ObjectReference>,
    gas_to_resolve: Vec<ObjectId>,
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

impl TransactionBuilder<()> {
    /// Instantiate a new PTB.
    pub fn new(sender: Address) -> TransactionBuilder<()> {
        TransactionBuilder {
            inputs: Default::default(),
            commands: Default::default(),
            gas: Default::default(),
            gas_to_resolve: Default::default(),
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
            gas_to_resolve: self.gas_to_resolve,
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
    fn input(&mut self, param: UnresolvedInput) -> Argument {
        if self
            .gas
            .iter()
            .any(
                |g| {
                    matches!(&param, UnresolvedInput::ImmutableOrOwned(id) if id == g.object_id())
                    || matches!(&param, UnresolvedInput::Resolved(Input::ImmutableOrOwned(id)) if id.object_id() == g.object_id())
                },
            ) ||
            self
                .gas_to_resolve
                .iter()
                .any(
                    |g| {
                        matches!(&param, UnresolvedInput::ImmutableOrOwned(id) if id == g)
                        || matches!(&param, UnresolvedInput::Resolved(Input::ImmutableOrOwned(id)) if id.object_id() == g)
                    },
                )
        {
            return Argument::Gas;
        };
        if let Some(i) = self.inputs.iter().position(|i| i == &param) {
            return Argument::Input(i as _);
        }
        self.inputs.push(param);
        Argument::Input((self.inputs.len() - 1) as _)
    }

    /// Add a pure input using the BCS serialized bytes
    pub fn pure_bytes(&mut self, bytes: Vec<u8>) -> Argument {
        self.input(UnresolvedInput::Resolved(Input::Pure { value: bytes }))
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

    /// Get the value for the given string in the named commands map
    pub fn get_named_command(&self, name: &str) -> Option<Argument> {
        self.named_commands.get(name).copied()
    }
}

impl TransactionBuilder<()> {
    /// Set the gas coins that will be consumed. Optional.
    pub fn gas(&mut self, obj_ref: ObjectReference) -> &mut Self {
        self.gas.push(obj_ref);
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
        let primary_coin = self.input(UnresolvedInput::Resolved(Input::ImmutableOrOwned(
            primary_coin,
        )));
        let mut consumed = Vec::new();
        for coin in consumed_coins {
            consumed.push(self.input(UnresolvedInput::Resolved(Input::ImmutableOrOwned(coin))));
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
        name: impl NamedCommands,
    ) -> &mut Self {
        let coin = self.input(UnresolvedInput::Resolved(Input::ImmutableOrOwned(coin)));
        let split_amounts = split_amounts.into_iter().map(|v| self.pure(v)).collect();
        self.command(Command::SplitCoins(SplitCoins {
            coin,
            amounts: split_amounts,
        }));
        name.push_named_commands(self);
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
            .map(|o| self.input(UnresolvedInput::Resolved(Input::ImmutableOrOwned(o))))
            .collect();
        let cmd = Command::TransferObjects(TransferObjects {
            objects,
            address: self.pure(recipient),
        });
        self.commands.push(cmd);
        self
    }

    fn resolve_inputs(&mut self) -> Result<Vec<Input>, Error> {
        let mut inputs = Vec::new();
        for input in self.inputs.drain(..) {
            match input {
                UnresolvedInput::Resolved(input) => inputs.push(input),
                _ => {
                    return Err(Error::Input(
                        "cannot resolve inputs without client".to_owned(),
                    ));
                }
            }
        }
        Ok(inputs)
    }

    /// Convert this builder into a transaction.
    pub fn finish(mut self) -> Result<Transaction, Error> {
        if !self.gas_to_resolve.is_empty() {
            return Err(Error::Input(
                "gas cannot be resolved without a client".to_owned(),
            ));
        }
        let Some(price) = self.gas_price else {
            return Err(Error::MissingGasPrice);
        };
        Ok(Transaction {
            kind: iota_types::TransactionKind::ProgrammableTransaction(
                iota_types::ProgrammableTransaction {
                    inputs: self.resolve_inputs()?,
                    commands: self.commands,
                },
            ),
            sender: self.sender,
            gas_payment: GasPayment {
                objects: self.gas,
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
        self.gas_to_resolve.push(object_id);
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
        self.commands.push(cmd);
        self
    }

    /// Merge multiple coins into one.
    pub fn merge_coins(
        &mut self,
        primary_coin: ObjectId,
        consumed_coins: impl IntoIterator<Item = ObjectId> + Send,
    ) -> &mut Self {
        let primary_coin = self.input(UnresolvedInput::ImmutableOrOwned(primary_coin));
        let mut consumed = Vec::new();
        for coin in consumed_coins {
            consumed.push(self.input(UnresolvedInput::ImmutableOrOwned(coin)));
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
        name: impl NamedCommands,
    ) -> &mut Self {
        let coin = self.input(UnresolvedInput::ImmutableOrOwned(coin));
        let split_amounts = split_amounts.into_iter().map(|v| self.pure(v)).collect();
        self.command(Command::SplitCoins(SplitCoins {
            coin,
            amounts: split_amounts,
        }));
        name.push_named_commands(self);
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
        name: impl NamedCommand,
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
        name.push_named_commands(self);
        self
    }

    /// Make a move vector from a list of elements.
    pub fn make_move_vec<U: PTBArguments + MoveType>(
        &mut self,
        elements: impl IntoIterator<Item = U>,
        name: impl NamedCommand,
    ) -> &mut Self {
        let mut args = Vec::new();
        for e in elements {
            args.extend(e.args(self));
        }
        let cmd = Command::MakeMoveVector(MakeMoveVector {
            type_: Some(U::type_tag()),
            elements: args,
        });
        self.commands.push(cmd);
        name.push_named_commands(self);
        self
    }

    /// Manually set a command with an optional name
    pub fn named_command(&mut self, cmd: Command, name: impl NamedCommands) -> &mut Self {
        self.commands.push(cmd);
        name.push_named_commands(self);
        self
    }

    async fn resolve_inputs(&mut self) -> Result<Vec<Input>, Error> {
        let mut inputs = Vec::new();
        for input in self.inputs.drain(..) {
            let (object_id, mutable) = match input {
                UnresolvedInput::ImmutableOrOwned(object_id)
                | UnresolvedInput::Receiving(object_id) => (object_id, false),
                UnresolvedInput::Shared { object_id, mutable } => (object_id, mutable),
                UnresolvedInput::Resolved(input) => {
                    inputs.push(input);
                    continue;
                }
            };
            let obj = self
                .client
                .object(object_id, None)
                .await
                .map_err(Error::Client)?
                .ok_or_else(|| Error::Input(format!("missing object {object_id}")))?;

            inputs.push(match obj.owner() {
                Owner::Address(_) | Owner::Object(_) | Owner::Immutable => Input::ImmutableOrOwned(
                    ObjectReference::new(object_id, obj.version(), obj.digest()),
                ),
                Owner::Shared(version) => Input::Shared {
                    object_id,
                    initial_shared_version: *version,
                    mutable,
                },
            });
        }
        Ok(inputs)
    }

    async fn resolve_gas(&mut self) -> Result<(), Error> {
        for gas_to_resolve in self.gas_to_resolve.drain(..) {
            let obj = self
                .client
                .object(gas_to_resolve, None)
                .await
                .map_err(Error::Client)?
                .ok_or_else(|| Error::Input(format!("missing object {gas_to_resolve}")))?;

            let obj_ref = match obj.owner() {
                Owner::Address(_) | Owner::Object(_) | Owner::Immutable => {
                    ObjectReference::new(gas_to_resolve, obj.version(), obj.digest())
                }
                Owner::Shared(_) => return Err(Error::WrongGasObject),
            };

            self.gas.push(obj_ref);
        }
        Ok(())
    }

    /// Convert this builder into a transaction.
    pub async fn finish(mut self) -> Result<Transaction, Error> {
        self.resolve_gas().await?;
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
                    inputs: self.resolve_inputs().await?,
                    commands: self.commands,
                },
            ),
            sender: self.sender,
            gas_payment: GasPayment {
                objects: self.gas,
                owner: self.sponsor.unwrap_or(self.sender),
                price,
                budget: self.gas_budget.unwrap_or(0),
            },
            expiration: self.expiration,
        };
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
        self.resolve_gas().await?;
        let price = match self.gas_price {
            Some(price) => price,
            None => self
                .client
                .reference_gas_price(None)
                .await
                .map_err(Error::Client)?
                .ok_or_else(|| Error::MissingGasPrice)?,
        };
        let txn = Transaction {
            kind: iota_types::TransactionKind::ProgrammableTransaction(
                iota_types::ProgrammableTransaction {
                    inputs: self.resolve_inputs().await?,
                    commands: self.commands,
                },
            ),
            sender: self.sender,
            gas_payment: GasPayment {
                objects: self.gas,
                owner: self.sponsor.unwrap_or(self.sender),
                price,
                budget: self.gas_budget.unwrap_or(0),
            },
            expiration: self.expiration,
        };
        println!("{txn:#?}");
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

/// A builder for a move call command within a programmable transaction.
#[derive(Debug)]
pub struct MoveCallCommandBuilder<'a, C, G: MoveTypes = (), A = ()> {
    package: ObjectId,
    module: Identifier,
    function: Identifier,
    args: Option<A>,
    generics: Result<PhantomData<G>, Vec<TypeTag>>,
    ptb: &'a mut TransactionBuilder<C>,
}

impl<'a, G: MoveTypes, A: PTBArguments> MoveCallCommandBuilder<'a, Client, G, A> {
    /// Instantiate a move call command builder.
    pub fn new(
        ptb: &'a mut TransactionBuilder<Client>,
        package_id: ObjectId,
        module: &str,
        function: &str,
    ) -> Self {
        Self {
            package: package_id,
            module: Identifier::new(module)
                .unwrap_or_else(|_| panic!("invalid identifier: {module}")),
            function: Identifier::new(function)
                .unwrap_or_else(|_| panic!("invalid identifier: {function}")),
            args: None,
            generics: Ok(PhantomData),
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
            generics: Ok(PhantomData),
            ptb: self.ptb,
        }
    }

    /// Set the type arguments manually. Optional.
    pub fn type_tags(
        self,
        tags: impl IntoIterator<Item = TypeTag>,
    ) -> MoveCallCommandBuilder<'a, Client, (), A> {
        MoveCallCommandBuilder {
            package: self.package,
            module: self.module,
            function: self.function,
            args: self.args,
            generics: Err(tags.into_iter().collect()),
            ptb: self.ptb,
        }
    }

    /// Finish the move call and return the PTB.
    pub fn end(self) -> &'a mut TransactionBuilder<Client> {
        let args = if let Some(a) = self.args {
            a.args(self.ptb)
        } else {
            Vec::new()
        };

        self.ptb.command(Command::MoveCall(MoveCall {
            package: self.package,
            module: self.module,
            function: self.function,
            type_arguments: match self.generics {
                Ok(_) => G::type_tags(),
                Err(t) => t,
            },
            arguments: args,
        }));

        self.ptb
    }

    /// Finish the move call by naming the output and return the PTB.
    pub fn result(self, name: impl NamedCommands) -> &'a mut TransactionBuilder<Client> {
        let ptb = self.end();

        name.push_named_commands(ptb);

        ptb
    }
}

impl<'a, G: MoveTypes> MoveCallCommandBuilder<'a, (), G, Vec<Argument>> {
    /// Instantiate a move call command builder.
    pub fn new(
        ptb: &'a mut TransactionBuilder<()>,
        package_id: ObjectId,
        module: &str,
        function: &str,
    ) -> Self {
        Self {
            package: package_id,
            module: Identifier::new(module)
                .unwrap_or_else(|_| panic!("invalid identifier: {module}")),
            function: Identifier::new(function)
                .unwrap_or_else(|_| panic!("invalid identifier: {function}")),
            args: None,
            generics: Ok(PhantomData),
            ptb,
        }
    }

    /// Set the call params. Optional.
    pub fn params(
        self,
        params: impl IntoIterator<Item = ObjectReference>,
    ) -> MoveCallCommandBuilder<'a, (), G, Vec<Argument>> {
        MoveCallCommandBuilder {
            package: self.package,
            module: self.module,
            function: self.function,
            args: Some(
                params
                    .into_iter()
                    .map(|o| {
                        self.ptb
                            .input(UnresolvedInput::Resolved(Input::ImmutableOrOwned(o)))
                    })
                    .collect::<Vec<_>>(),
            ),
            generics: self.generics,
            ptb: self.ptb,
        }
    }

    /// Set the generic type arguments. Optional.
    pub fn generics<U: MoveTypes>(self) -> MoveCallCommandBuilder<'a, (), U, Vec<Argument>> {
        MoveCallCommandBuilder {
            package: self.package,
            module: self.module,
            function: self.function,
            args: self.args,
            generics: Ok(PhantomData),
            ptb: self.ptb,
        }
    }

    /// Set the type arguments manually. Optional.
    pub fn type_tags(
        self,
        tags: impl IntoIterator<Item = TypeTag>,
    ) -> MoveCallCommandBuilder<'a, (), (), Vec<Argument>> {
        MoveCallCommandBuilder {
            package: self.package,
            module: self.module,
            function: self.function,
            args: self.args,
            generics: Err(tags.into_iter().collect()),
            ptb: self.ptb,
        }
    }

    /// Finish the move call and return the PTB.
    pub fn end(self) -> &'a mut TransactionBuilder<()> {
        let args = self.args.unwrap_or_default();

        self.ptb.command(Command::MoveCall(MoveCall {
            package: self.package,
            module: self.module,
            function: self.function,
            type_arguments: match self.generics {
                Ok(_) => G::type_tags(),
                Err(t) => t,
            },
            arguments: args,
        }));

        self.ptb
    }

    /// Finish the move call by naming the output and return the PTB.
    pub fn result(self, name: impl NamedCommands) -> &'a mut TransactionBuilder<()> {
        let ptb = self.end();

        name.push_named_commands(ptb);

        ptb
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
    pub fn new(ptb: &'a mut TransactionBuilder<Client>, kind: impl Into<PublishType>) -> Self {
        let module = match kind.into() {
            PublishType::Path(_path) => todo!("load the package from the path"),
            PublishType::Compiled(m) => m,
        };
        let cap = ptb.command(Command::Publish(Publish {
            modules: module.modules,
            dependencies: module.dependencies,
        }));
        Self { ptb, cap }
    }

    /// Get the package ID from the UpgradeCap so that it can be used for future
    /// commands.
    ///
    /// **NOTE:** This is currently not usable for move calls because the IOTA
    /// PTB does not support using an argument for the package ID.
    pub fn package_id(self, name: impl NamedCommand) -> &'a mut TransactionBuilder<Client> {
        self.ptb
            .move_call(Address::TWO, "package", "upgrade_package")
            .params(self.cap)
            .result(name);
        self.ptb
    }

    /// Finish the move call and return the UpgradeCap.
    pub fn upgrade_cap(self, name: impl NamedCommand) -> &'a mut TransactionBuilder<Client> {
        name.push_named_commands(self.ptb);

        self.ptb
    }
}

/// A trait which defines arguments for a [`TransactionBuilder`].
pub trait PTBArguments {
    /// Get the arguments.
    fn args(&self, ptb: &mut TransactionBuilder<Client>) -> Vec<Argument> {
        let mut args = Vec::new();
        self.push_args(ptb, &mut args);
        args
    }

    /// Push the args onto the list.
    fn push_args(&self, ptb: &mut TransactionBuilder<Client>, args: &mut Vec<Argument>);
}

macro_rules! impl_ptb_args_tuple {
    ($($tup:ident.$idx:tt),+$(,)?) => {
        impl<$($tup),+> PTBArguments for ($($tup),+)
        where $($tup: PTBArguments),+
        {
            fn push_args(&self, ptb: &mut TransactionBuilder<Client>, args: &mut Vec<Argument>) {
                $(
                    self.$idx.push_args(ptb, args);
                )+
            }
        }
    };
}
impl_ptb_args_tuple!(T1.0, T2.1);
impl_ptb_args_tuple!(T1.0, T2.1, T3.2);
impl_ptb_args_tuple!(T1.0, T2.1, T3.2, T4.3);
impl_ptb_args_tuple!(T1.0, T2.1, T3.2, T4.3, T5.4);

impl<T: MoveParam> PTBArguments for T {
    fn push_args(&self, ptb: &mut TransactionBuilder<Client>, args: &mut Vec<Argument>) {
        let arg = match self.param() {
            ParamType::Object(id) => ptb.input(UnresolvedInput::ImmutableOrOwned(id)),
            ParamType::Pure(v) => ptb.pure_bytes(v),
        };
        args.push(arg);
    }
}

impl<T: PTBArguments> PTBArguments for Vec<T> {
    fn push_args(&self, ptb: &mut TransactionBuilder<Client>, args: &mut Vec<Argument>) {
        for val in self {
            val.push_args(ptb, args);
        }
    }
}

impl<T: PTBArguments> PTBArguments for std::sync::Arc<T> {
    fn push_args(&self, ptb: &mut TransactionBuilder<Client>, args: &mut Vec<Argument>) {
        self.as_ref().push_args(ptb, args);
    }
}

impl PTBArguments for Box<dyn PTBArguments> {
    fn push_args(&self, ptb: &mut TransactionBuilder<Client>, args: &mut Vec<Argument>) {
        self.as_ref().push_args(ptb, args);
    }
}

impl PTBArguments for Argument {
    fn push_args(&self, _: &mut TransactionBuilder<Client>, args: &mut Vec<Argument>) {
        args.push(*self);
    }
}

/// Allows specifying mutable parameters.
pub struct Mut<T>(pub T);

impl<T: MoveParam> PTBArguments for Mut<T> {
    fn push_args(&self, ptb: &mut TransactionBuilder<Client>, args: &mut Vec<Argument>) {
        let arg = match self.0.param() {
            ParamType::Object(id) => ptb.input(UnresolvedInput::Shared {
                object_id: id,
                mutable: true,
            }),
            ParamType::Pure(v) => ptb.pure_bytes(v),
        };
        args.push(arg);
    }
}

/// Allows specifying receiving parameters.
pub struct Receiving<T>(pub T);

impl<T: MoveParam> PTBArguments for Receiving<T> {
    fn push_args(&self, ptb: &mut TransactionBuilder<Client>, args: &mut Vec<Argument>) {
        let arg = match self.0.param() {
            ParamType::Object(id) => ptb.input(UnresolvedInput::Receiving(id)),
            ParamType::Pure(v) => ptb.pure_bytes(v),
        };
        args.push(arg);
    }
}

/// The result of a previous command by name.
pub struct Res(pub &'static str);

impl PTBArguments for Res {
    fn push_args(&self, ptb: &mut TransactionBuilder<Client>, args: &mut Vec<Argument>) {
        if let Some(arg) = ptb.named_commands.get(self.0) {
            args.push(*arg);
        } else {
            panic!("no command named `{}` exists", self.0)
        }
    }
}

/// A trait that defines a named command, either a string or nothing.
pub trait NamedCommand {
    /// Get the named command argument.
    fn named_command<C>(&self, ptb: &mut TransactionBuilder<C>) -> Argument;

    /// Push the named command to the PTB.
    fn push_named_command<C>(self, arg: Argument, ptb: &mut TransactionBuilder<C>);
}

impl NamedCommand for () {
    fn named_command<C>(&self, ptb: &mut TransactionBuilder<C>) -> Argument {
        Argument::Result((ptb.commands.len() - 1) as _)
    }

    fn push_named_command<C>(self, _: Argument, _: &mut TransactionBuilder<C>) {}
}

impl NamedCommand for &str {
    fn named_command<C>(&self, ptb: &mut TransactionBuilder<C>) -> Argument {
        Argument::Result((ptb.commands.len() - 1) as _)
    }

    fn push_named_command<C>(self, arg: Argument, ptb: &mut TransactionBuilder<C>) {
        ptb.named_commands.insert(self.to_owned(), arg);
    }
}

impl NamedCommand for String {
    fn named_command<C>(&self, ptb: &mut TransactionBuilder<C>) -> Argument {
        Argument::Result((ptb.commands.len() - 1) as _)
    }

    fn push_named_command<C>(self, arg: Argument, ptb: &mut TransactionBuilder<C>) {
        ptb.named_commands.insert(self.to_owned(), arg);
    }
}

impl<T: NamedCommand> NamedCommand for Option<T> {
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

impl<T: NamedCommand> NamedCommands for Vec<T> {
    fn push_named_commands<C>(self, ptb: &mut TransactionBuilder<C>) {
        for (i, v) in self.into_iter().enumerate() {
            let arg = Argument::NestedResult((ptb.commands.len() - 1) as _, i as _);
            v.push_named_command(arg, ptb);
        }
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
