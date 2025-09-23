// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use iota_graphql_client::Client;
use iota_types::{Identifier, ObjectId, ObjectReference, TypeTag};

use crate::{
    TransactionBuilder,
    builder::ptb_arguments::PTBArguments,
    types::MoveTypes,
    unresolved::{Argument, Command, InputKind, MoveCall},
};

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
                        self.ptb.input(
                            InputKind::Input(iota_types::Input::ImmutableOrOwned(o)),
                            false,
                        )
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
}
