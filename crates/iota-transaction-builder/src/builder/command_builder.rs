// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_graphql_client::{Client, DryRunResult};
use iota_types::{Address, ObjectId, ObjectReference, Transaction, TransactionEffects, TypeTag};

use crate::{
    PTBArguments, TransactionBuilder,
    builder::named_commands::{NamedCommand, NamedCommands},
    error::Error,
    types::{MoveType, MoveTypes},
    unresolved::{Argument, Command, MakeMoveVector, MoveCall, Publish, SplitCoins},
};

/// A wrapper which allows optionally setting names and returning arguments from
/// the previous command.
pub struct CommandBuilder<'a, C, L> {
    pub(crate) ptb: &'a mut TransactionBuilder<C>,
    pub(crate) last_command: L,
}

impl<'a, C, L: Into<Command>> CommandBuilder<'a, C, L> {
    fn finish_command(self) -> &'a mut TransactionBuilder<C> {
        let Self { ptb, last_command } = self;
        ptb.command(last_command.into());
        ptb
    }
}

impl<'a, C, L: Into<Command>> CommandBuilder<'a, C, L> {
    /// Set the name for the last command.
    pub fn name(self, name: impl NamedCommands) -> &'a mut TransactionBuilder<C> {
        name.push_named_commands(self.ptb);
        self.finish_command()
    }

    /// Get the argument representing the last command.
    pub fn arg(&self) -> Argument {
        Argument::Result(self.ptb.commands.len() as _)
    }

    /// Get the current set gas coins.
    pub fn get_gas(&self) -> impl Iterator<Item = ObjectId> + '_ {
        self.ptb.get_gas()
    }

    /// Set the gas budget. Optional.
    pub fn gas_budget(self, gas_budget: u64) -> &'a mut TransactionBuilder<C> {
        self.ptb.gas_budget(gas_budget);
        self.finish_command()
    }

    /// Set the gas price. Optional.
    pub fn gas_price(self, gas_price: u64) -> &'a mut TransactionBuilder<C> {
        self.ptb.gas_price(gas_price);
        self.finish_command()
    }

    /// Set the sponsor. Optional.
    pub fn sponsor(self, sponsor: Address) -> &'a mut TransactionBuilder<C> {
        self.ptb.sponsor(sponsor);
        self.finish_command()
    }

    /// Set the expiration. Optional.
    pub fn expiration(self, expiration: u64) -> &'a mut TransactionBuilder<C> {
        self.ptb.expiration(expiration);
        self.finish_command()
    }

    /// Get the value for the given string in the named commands map
    pub fn get_named_command(&self, name: &str) -> Option<Argument> {
        self.ptb.get_named_command(name)
    }

    /// Transfer IOTA to a recipient address.
    pub fn transfer_iota(
        self,
        recipient: Address,
        amount: impl Into<Option<u64>> + Send,
    ) -> &'a mut TransactionBuilder<C> {
        self.ptb.transfer_iota(recipient, amount)
    }
}

impl<'a, L: Into<Command>> CommandBuilder<'a, (), L> {
    /// Set the gas coins that will be consumed. Optional.
    pub fn gas(self, obj_ref: ObjectReference) -> &'a mut TransactionBuilder<()> {
        self.ptb.gas(obj_ref);
        self.finish_command()
    }

    /// Begin building a move call.
    pub fn move_call(
        self,
        package_id: ObjectId,
        module: &'static str,
        function: &'static str,
    ) -> CommandBuilder<'a, (), MoveCall> {
        self.finish_command()
            .move_call(package_id, module, function)
    }

    /// Merge multiple coins into one.
    pub fn merge_coins(
        self,
        primary_coin: ObjectReference,
        consumed_coins: impl IntoIterator<Item = ObjectReference> + Send,
    ) -> &'a mut TransactionBuilder<()> {
        self.finish_command()
            .merge_coins(primary_coin, consumed_coins)
    }

    /// Split a coin into many.
    pub fn split_coins(
        self,
        coin: ObjectReference,
        split_amounts: impl IntoIterator<Item = u64> + Send,
    ) -> CommandBuilder<'a, (), SplitCoins> {
        self.finish_command().split_coins(coin, split_amounts)
    }

    /// Transfer objects to a recipient address.
    pub fn transfer_objects(
        self,
        recipient: Address,
        objects: impl IntoIterator<Item = ObjectReference>,
    ) -> &'a mut TransactionBuilder<()> {
        self.finish_command().transfer_objects(recipient, objects)
    }

    /// Make a move vector from a list of elements.
    pub fn make_move_vec(
        self,
        elements: impl IntoIterator<Item = Argument>,
        type_tag: impl Into<Option<TypeTag>>,
    ) -> CommandBuilder<'a, (), MakeMoveVector> {
        self.finish_command().make_move_vec(elements, type_tag)
    }

    /// Convert this builder into a transaction.
    pub fn finish(self) -> Result<Transaction, Error> {
        self.finish_command().clone().finish()
    }
}

impl<'a, L: Into<Command>> CommandBuilder<'a, Client, L> {
    /// Set the gas coins that will be consumed. Optional.
    pub fn gas(self, object_id: ObjectId) -> &'a mut TransactionBuilder<Client> {
        self.finish_command().gas(object_id)
    }

    /// Begin building a move call.
    pub fn move_call(
        self,
        package_id: ObjectId,
        module: &'static str,
        function: &'static str,
    ) -> CommandBuilder<'a, Client, MoveCall> {
        self.finish_command()
            .move_call(package_id, module, function)
    }

    /// Merge multiple coins into one.
    pub fn merge_coins(
        self,
        primary_coin: ObjectId,
        consumed_coins: impl IntoIterator<Item = ObjectId> + Send,
    ) -> &'a mut TransactionBuilder<Client> {
        self.finish_command()
            .merge_coins(primary_coin, consumed_coins)
    }

    /// Split a coin into many.
    pub fn split_coins(
        self,
        coin: ObjectId,
        split_amounts: impl IntoIterator<Item = u64> + Send,
    ) -> CommandBuilder<'a, Client, SplitCoins> {
        self.finish_command().split_coins(coin, split_amounts)
    }

    /// Transfer objects to a recipient address.
    pub fn transfer_objects<U: PTBArguments>(
        self,
        recipient: Address,
        objects: U,
    ) -> &'a mut TransactionBuilder<Client> {
        self.finish_command().transfer_objects(recipient, objects)
    }

    /// Make a move vector from a list of elements.
    pub fn make_move_vec<U: PTBArguments + MoveType>(
        self,
        elements: impl IntoIterator<Item = U>,
    ) -> CommandBuilder<'a, Client, MakeMoveVector> {
        self.finish_command().make_move_vec(elements)
    }

    /// Convert this builder into a transaction.
    pub async fn finish(self) -> Result<Transaction, Error> {
        self.finish_command().clone().finish().await
    }

    /// Dry run the transaction.
    pub async fn dry_run(self, skip_checks: bool) -> Result<DryRunResult, Error> {
        self.finish_command().clone().dry_run(skip_checks).await
    }

    /// Execute the transaction and optionally wait for finalization.
    pub async fn execute(
        self,
        keypairs: &[iota_crypto::simple::SimpleKeypair],
        wait_for_finalization: bool,
    ) -> Result<Option<TransactionEffects>, Error> {
        self.finish_command()
            .clone()
            .execute(keypairs, wait_for_finalization)
            .await
    }
}

impl<'a> CommandBuilder<'a, (), MoveCall> {
    /// Set the call params. Optional.
    pub fn params(mut self, params: impl IntoIterator<Item = Argument>) -> Self {
        self.last_command.arguments = params.into_iter().collect();
        self
    }

    /// Set the generic type arguments. Optional.
    pub fn generics<G: MoveTypes>(mut self) -> Self {
        self.last_command.type_arguments = G::type_tags();
        self
    }

    /// Set the type arguments manually. Optional.
    pub fn type_tags(mut self, tags: impl IntoIterator<Item = TypeTag>) -> Self {
        self.last_command.type_arguments = tags.into_iter().collect();
        self
    }
}

impl<'a> CommandBuilder<'a, Client, MoveCall> {
    /// Set the call params. Optional.
    pub fn params<U: PTBArguments>(mut self, params: U) -> Self {
        self.last_command.arguments = params.args(self.ptb);
        self
    }

    /// Set the generic type arguments. Optional.
    pub fn generics<G: MoveTypes>(mut self) -> Self {
        self.last_command.type_arguments = G::type_tags();
        self
    }

    /// Set the type arguments manually. Optional.
    pub fn type_tags(mut self, tags: impl IntoIterator<Item = TypeTag>) -> Self {
        self.last_command.type_arguments = tags.into_iter().collect();
        self
    }
}

impl<'a> CommandBuilder<'a, (), Publish> {
    /// Get the package ID from the UpgradeCap so that it can be used for future
    /// commands.
    pub fn package_id(self, name: impl NamedCommand) -> &'a mut TransactionBuilder<()> {
        let cap = self.arg();
        self.finish_command()
            .move_call(Address::TWO, "package", "upgrade_package")
            .params([cap])
            .name(name)
    }

    /// Finish the publish call and return the UpgradeCap.
    pub fn upgrade_cap(self, name: impl NamedCommand) -> &'a mut TransactionBuilder<()> {
        name.push_named_commands(self.ptb);

        self.finish_command()
    }
}

impl<'a> CommandBuilder<'a, Client, Publish> {
    /// Get the package ID from the UpgradeCap so that it can be used for future
    /// commands.
    pub fn package_id(self, name: impl NamedCommand) -> &'a mut TransactionBuilder<Client> {
        let cap = self.arg();
        self.finish_command()
            .move_call(Address::TWO, "package", "upgrade_package")
            .params(cap)
            .name(name)
    }

    /// Finish the publish call and return the UpgradeCap.
    pub fn upgrade_cap(self, name: impl NamedCommand) -> &'a mut TransactionBuilder<Client> {
        name.push_named_commands(self.ptb);

        self.finish_command()
    }
}
