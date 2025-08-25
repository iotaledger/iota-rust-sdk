// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, RwLock};

use crate::{
    error::Result,
    transaction_builder::unresolved::UnresolvedInput,
    types::{
        address::Address,
        object::ObjectId,
        struct_tag::Identifier,
        transaction::{Argument, Transaction},
        type_tag::TypeTag,
    },
};

mod unresolved;

/// A builder for creating transactions. Use [`finish`](Self::finish) to
/// finalize the transaction data.
#[derive(derive_more::From, uniffi::Object)]
pub struct TransactionBuilder(RwLock<iota_transaction_builder::TransactionBuilder>);

#[uniffi::export]
impl TransactionBuilder {
    /// Create a new transaction builder and initialize its elements to default.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self(iota_transaction_builder::TransactionBuilder::new().into())
    }

    /// Make a value available to the transaction as an input.
    pub fn input(&self, i: &UnresolvedInput) -> Argument {
        self.0
            .write()
            .expect("error writing to builder")
            .input(i.0.clone())
            .into()
    }

    /// Return the argument to be the gas object.
    pub fn gas(&self) -> Argument {
        self.0
            .read()
            .expect("error reading from builder")
            .gas()
            .into()
    }

    /// Add one or more gas objects to use to pay for the transaction.
    ///
    /// Most commonly the gas can be passed as a reference to an owned/immutable
    /// [`Object`](iota_types::Object), or can created using one of the of
    /// the constructors of the [`unresolved::Input`] enum, e.g.,
    /// [`unresolved::Input::owned`].
    pub fn add_gas_objects(&self, gas: Vec<Arc<UnresolvedInput>>) {
        self.0
            .write()
            .expect("error writing to builder")
            .add_gas_objects(gas.into_iter().map(|v| v.0.clone()));
    }

    /// Set the gas budget for the transaction.
    pub fn set_gas_budget(&self, budget: u64) {
        self.0
            .write()
            .expect("error writing to builder")
            .set_gas_budget(budget);
    }

    /// Set the gas price for the transaction.
    pub fn set_gas_price(&self, price: u64) {
        self.0
            .write()
            .expect("error writing to builder")
            .set_gas_price(price);
    }

    /// Set the sender of the transaction.
    pub fn set_sender(&self, sender: &Address) {
        self.0
            .write()
            .expect("error writing to builder")
            .set_sender(**sender);
    }

    /// Set the sponsor of the transaction.
    pub fn set_sponsor(&self, sponsor: &Address) {
        self.0
            .write()
            .expect("error writing to builder")
            .set_sponsor(**sponsor);
    }

    /// Set the expiration of the transaction to be a specific epoch.
    pub fn set_expiration(&self, epoch: u64) {
        self.0
            .write()
            .expect("error writing to builder")
            .set_expiration(epoch);
    }

    // Commands

    /// Call a Move function with the given arguments.
    ///
    /// - `function` is a structured representation of a
    ///   package::module::function argument, optionally with type arguments.
    ///
    /// The return value is a result argument that can be used in subsequent
    /// commands. If the move call returns multiple results, you can access
    /// them using the [`Argument::nested`] method.
    pub fn move_call(&self, function: Function, arguments: Vec<Arc<Argument>>) -> Argument {
        self.0
            .write()
            .expect("error writing to builder")
            .move_call(
                function.into(),
                arguments.into_iter().map(|v| **v).collect(),
            )
            .into()
    }

    /// Transfer a list of objects to the given address, without producing any
    /// result.
    pub fn transfer_objects(&self, objects: Vec<Arc<Argument>>, address: &Argument) {
        self.0
            .write()
            .expect("error writing to builder")
            .transfer_objects(objects.into_iter().map(|v| **v).collect(), **address);
    }

    /// Split a coin by the provided amounts, returning multiple results (as
    /// many as there are amounts). To access the results, use the
    /// [`Argument::nested`] method to access the desired coin by its index.
    pub fn split_coins(&self, coin: &Argument, amounts: Vec<Arc<Argument>>) -> Argument {
        self.0
            .write()
            .expect("error writing to builder")
            .split_coins(**coin, amounts.into_iter().map(|v| **v).collect())
            .into()
    }

    /// Merge a list of coins into a single coin, without producing any result.
    pub fn merge_coins(&self, coin: &Argument, coins_to_merge: Vec<Arc<Argument>>) {
        self.0
            .write()
            .expect("error writing to builder")
            .merge_coins(**coin, coins_to_merge.into_iter().map(|v| **v).collect());
    }

    /// Make a move vector from a list of elements. If the elements are not
    /// objects, or the vector is empty, a type must be supplied.
    /// It returns the Move vector as an argument, that can be used in
    /// subsequent commands.
    pub fn make_move_vec(
        &self,
        type_tag: Option<Arc<TypeTag>>,
        elements: Vec<Arc<Argument>>,
    ) -> Argument {
        self.0
            .write()
            .expect("error writing to builder")
            .make_move_vec(
                type_tag.map(|v| v.0.clone()),
                elements.into_iter().map(|v| **v).collect(),
            )
            .into()
    }

    /// Publish a list of modules with the given dependencies. The result is the
    /// `0x2::package::UpgradeCap` Move type. Note that the upgrade capability
    /// needs to be handled after this call:
    ///  - transfer it to the transaction sender or another address
    ///  - burn it
    ///  - wrap it for access control
    ///  - discard the it to make a package immutable
    ///
    /// The arguments required for this command are:
    ///  - `modules`: is the modules' bytecode to be published
    ///  - `dependencies`: is the list of IDs of the transitive dependencies of
    ///    the package
    pub fn publish(&self, modules: Vec<Vec<u8>>, dependencies: Vec<Arc<ObjectId>>) -> Argument {
        self.0
            .write()
            .expect("error writing to builder")
            .publish(modules, dependencies.into_iter().map(|v| **v).collect())
            .into()
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
    /// `0x2::package::authorize_upgrade` function,  and pass the package
    /// ID, the upgrade policy, and package digest.
    ///
    ///  Examples:
    ///  ### Upgrade a package with some pre-known data.
    ///
    ///  ```rust,ignore
    ///  use iota_graphql_client::Client;
    ///  use iota_sdk_types::unresolved;
    ///  use iota_transaction_builder::TransactionBuilder;
    ///  use iota_transaction_builder::Function;
    ///
    ///  let mut tx = TransactionBuilder::new();
    ///  let package_id = "0x...".parse().unwrap();
    ///  let upgrade_cap =
    /// tx.input(unresolved::Input::by_id("0x...".parse().unwrap()));
    ///  let upgrade_policy = tx.input(Serialized(&0u8));
    ///  // the digest of the new package that was compiled
    ///  let package_digest: &[u8] = &[
    ///       68, 89, 156, 51, 190, 35, 155, 216, 248, 49, 135, 170, 106, 42,
    ///       190, 4, 208, 59, 155, 89, 74, 63, 70, 95, 207, 78, 227, 22,
    ///       136, 146, 57, 79
    ///  ];
    ///  let digest_arg = tx.input(Serialized(&package_digest));
    ///
    ///  // we need this ticket to authorize the upgrade
    ///  let upgrade_ticket = tx.move_call(
    ///      Function::new(
    ///        "0x2".parse().unwrap(),
    ///         "package".parse().unwrap(),
    ///         "authorize_upgrade".parse().unwrap(),
    ///         vec![],
    ///      ),
    ///      vec![upgrade_cap, upgrade_policy, digest_arg],
    ///    );
    ///  // now we can upgrade the package
    ///  let upgrade_receipt = tx.upgrade(
    ///       updated_modules,
    ///       deps,
    ///       package_id,
    ///       upgrade_ticket,
    ///  );
    ///
    ///  // commit the upgrade
    ///  tx.move_call(
    ///       Function::new(
    ///          "0x2".parse().unwrap(),
    ///          "package".parse().unwrap(),
    ///          "commit_upgrade".parse().unwrap(),
    ///          vec![],
    ///      ),
    ///      vec![upgrade_cap, upgrade_receipt],
    ///  );
    ///
    ///  let client = Client::new_mainnet();
    ///  let tx = tx.resolve(&client)?;
    ///  ```
    pub fn upgrade(
        &self,
        modules: Vec<Vec<u8>>,
        dependencies: Vec<Arc<ObjectId>>,
        package: &ObjectId,
        ticket: &Argument,
    ) -> Argument {
        self.0
            .write()
            .expect("error writing to builder")
            .upgrade(
                modules,
                dependencies.into_iter().map(|v| **v).collect(),
                **package,
                **ticket,
            )
            .into()
    }

    /// Assuming everything is resolved, convert this transaction into the
    /// resolved form. Returns a [`Transaction`] if successful, or an `Error` if
    /// not.
    pub fn finish(&self) -> Result<Transaction> {
        Ok(self
            .0
            .read()
            .expect("error reading from builder")
            .clone()
            .finish()?
            .into())
    }
}

/// A separate type to support denoting a function by a more structured
/// representation.
#[derive(uniffi::Record)]
pub struct Function {
    /// The package that contains the module with the function.
    pub package: Arc<Address>,
    /// The module that contains the function.
    pub module: Arc<Identifier>,
    /// The function name.
    pub function: Arc<Identifier>,
    /// The type arguments for the function.
    pub type_args: Vec<Arc<TypeTag>>,
}

impl From<iota_transaction_builder::Function> for Function {
    fn from(value: iota_transaction_builder::Function) -> Self {
        Self {
            package: Arc::new(value.package.into()),
            module: Arc::new(value.module.into()),
            function: Arc::new(value.function.into()),
            type_args: value
                .type_args
                .into_iter()
                .map(Into::into)
                .map(Arc::new)
                .collect(),
        }
    }
}

impl From<Function> for iota_transaction_builder::Function {
    fn from(value: Function) -> Self {
        Self {
            package: **value.package,
            module: value.module.0.clone(),
            function: value.function.0.clone(),
            type_args: value.type_args.into_iter().map(|v| v.0.clone()).collect(),
        }
    }
}
