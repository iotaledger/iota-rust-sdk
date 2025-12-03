// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Defines the [`MoveAuthenticatorFnCall`] which represents a call to an
//! authenticator function in move which can authorize a transaction as part of
//! Account Abstraction.

use iota_types::TypeTag;

use crate::{PTBArgumentList, types::MoveTypes};

/// A function call to authorize a transaction via move.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct MoveAuthenticatorFnCall<I> {
    /// Input objects or primitive values
    pub inputs: I,
    /// Type arguments for the Move authenticate function
    pub type_arguments: Vec<TypeTag>,
}

impl<I: PTBArgumentList> MoveAuthenticatorFnCall<I> {
    /// Create a new move authenticator call with the function inputs.
    pub fn inputs(inputs: I) -> MoveAuthenticatorFnCall<I> {
        MoveAuthenticatorFnCall {
            inputs,
            type_arguments: Default::default(),
        }
    }
}

impl<I> MoveAuthenticatorFnCall<I> {
    /// Set the move authenticator call type parameters.
    pub fn generics<G: MoveTypes>(self) -> MoveAuthenticatorFnCall<I> {
        MoveAuthenticatorFnCall {
            inputs: self.inputs,
            type_arguments: G::type_tags(),
        }
    }
}

impl<I> MoveAuthenticatorFnCall<I> {
    /// Set the move authenticator call type parameters manually.
    pub fn type_tags(self, tags: impl IntoIterator<Item = TypeTag>) -> MoveAuthenticatorFnCall<I> {
        MoveAuthenticatorFnCall {
            inputs: self.inputs,
            type_arguments: tags.into_iter().collect(),
        }
    }
}
