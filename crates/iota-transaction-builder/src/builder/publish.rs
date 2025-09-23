// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_graphql_client::Client;
use iota_types::Address;

use crate::{
    TransactionBuilder,
    builder::named_commands::{NamedCommand, NamedCommands},
    publish_type::PublishType,
    unresolved::{Argument, Command, Publish},
};

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
            .end()
            .name(name);
        self.ptb
    }

    /// Finish the move call and return the UpgradeCap.
    pub fn upgrade_cap(self, name: impl NamedCommand) -> &'a mut TransactionBuilder<Client> {
        name.push_named_commands(self.ptb);

        self.ptb
    }
}
