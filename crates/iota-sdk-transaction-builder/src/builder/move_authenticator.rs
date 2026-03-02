// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Defines the [`MoveAuthenticator`] builder that represents a call to an
//! authenticator function in move which can authorize a transaction as part of
//! Account Abstraction.

use iota_types::{
    MoveAuthenticator, MoveAuthenticatorV1, ObjectId, ObjectReference, Owner, TypeTag,
};

use crate::{
    ClientMethods, PTBArgumentList, error::Error, types::MoveTypes, unresolved::InputKind,
};

/// A function call to authorize a transaction via move.
#[derive(Debug, Clone)]
pub struct MoveAuthenticatorBuilder {
    /// Input objects or primitive values
    call_args: Vec<InputKind>,
    /// Type arguments for the Move authenticate function
    type_args: Vec<TypeTag>,
    /// The account ID, which is the sender of the transaction.
    account_id: ObjectId,
}

impl MoveAuthenticatorBuilder {
    /// Create a new Move Authenticator builder from an account ID, which is the
    /// sender of a transaction that this will be used to authenticate.
    pub fn new(account_id: ObjectId) -> Self {
        Self {
            call_args: Default::default(),
            type_args: Default::default(),
            account_id,
        }
    }

    /// Set the move authenticator call inputs.
    pub fn call_args<I: PTBArgumentList>(mut self, call_args: I) -> Self {
        self.call_args = call_args.inputs();
        self
    }

    /// Set the move authenticator call type parameters.
    pub fn generics<G: MoveTypes>(mut self) -> Self {
        self.type_args = G::type_tags();
        self
    }

    /// Set the move authenticator call type parameters manually.
    pub fn type_args(mut self, tags: impl IntoIterator<Item = TypeTag>) -> Self {
        self.type_args = tags.into_iter().collect();
        self
    }

    /// Resolve this move authenticator builder into a [`MoveAuthenticator`]
    /// which can be used to execute the given transaction.
    pub async fn finish(self, client: impl ClientMethods) -> Result<MoveAuthenticator, Error> {
        let account = client
            .object(self.account_id, None)
            .await
            .map_err(Error::client)?
            .ok_or_else(|| Error::Input(format!("missing account {}", self.account_id)))?;

        let mut call_args = Vec::new();
        for input in self.call_args {
            call_args.push(match input {
                InputKind::ImmutableOrOwned(object_id)
                | InputKind::Input(iota_types::Input::ImmutableOrOwned(ObjectReference {
                    object_id,
                    ..
                })) => {
                    let obj = client
                        .object(object_id, None)
                        .await
                        .map_err(Error::client)?
                        .ok_or_else(|| {
                            Error::InvalidMoveAuthArg(format!("missing object {object_id}"))
                        })?;
                    if !obj.owner().is_immutable() {
                        return Err(Error::InvalidMoveAuthArg(
                            "call arguments must not be owned".to_owned(),
                        ));
                    }
                    iota_types::Input::ImmutableOrOwned(obj.object_ref())
                }
                InputKind::Shared { object_id, mutable }
                | InputKind::Input(iota_types::Input::Shared(
                    iota_types::SharedObjectReference {
                        object_id, mutable, ..
                    },
                )) => {
                    let obj = client
                        .object(object_id, None)
                        .await
                        .map_err(Error::client)?
                        .ok_or_else(|| {
                            Error::InvalidMoveAuthArg(format!("missing object {object_id}"))
                        })?;

                    let Owner::Shared(version) = obj.owner() else {
                        return Err(Error::InvalidMoveAuthArg(format!(
                            "object {object_id} was passed as shared, but is not"
                        )));
                    };

                    iota_types::Input::Shared(iota_types::SharedObjectReference {
                        object_id,
                        initial_shared_version: *version,
                        mutable,
                    })
                }
                InputKind::Receiving(_) | InputKind::Input(iota_types::Input::Receiving(_)) => {
                    return Err(Error::InvalidMoveAuthArg(
                        "call arguments must not be receiving".to_owned(),
                    ));
                }
                InputKind::Input(input) => input.clone(),
            })
        }
        Ok(match account.owner() {
            Owner::Immutable => MoveAuthenticator::V1(MoveAuthenticatorV1::new_immutable(
                call_args,
                self.type_args,
                account.object_ref(),
            )),
            Owner::Shared(version) => MoveAuthenticator::V1(MoveAuthenticatorV1::new_shared(
                call_args,
                self.type_args,
                account.object_id(),
                *version,
            )),
            _ => {
                return Err(Error::InvalidMoveAuthAccount(
                    "account must be immutable or shared".to_owned(),
                ));
            }
        })
    }
}
