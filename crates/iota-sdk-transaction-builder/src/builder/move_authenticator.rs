// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Defines the [`MoveAuthenticatorArgs`] which represents a call to an
//! authenticator function in move which can authorize a transaction as part of
//! Account Abstraction.

use iota_types::TypeTag;

use crate::{PTBArgumentList, types::MoveTypes};

/// A function call to authorize a transaction via move.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct MoveAuthenticatorArgs<I> {
    /// Input objects or primitive values
    pub call_args: I,
    /// Type arguments for the Move authenticate function
    pub type_args: Vec<TypeTag>,
}

impl<I: PTBArgumentList> MoveAuthenticatorArgs<I> {
    /// Create a new move authenticator call with the function inputs.
    pub fn inputs(call_args: I) -> MoveAuthenticatorArgs<I> {
        MoveAuthenticatorArgs {
            call_args,
            type_args: Default::default(),
        }
    }
}

impl<I> MoveAuthenticatorArgs<I> {
    /// Set the move authenticator call type parameters.
    pub fn generics<G: MoveTypes>(self) -> MoveAuthenticatorArgs<I> {
        MoveAuthenticatorArgs {
            call_args: self.call_args,
            type_args: G::type_tags(),
        }
    }

    /// Set the move authenticator call type parameters manually.
    pub fn type_tags(self, tags: impl IntoIterator<Item = TypeTag>) -> MoveAuthenticatorArgs<I> {
        MoveAuthenticatorArgs {
            call_args: self.call_args,
            type_args: tags.into_iter().collect(),
        }
    }
}
