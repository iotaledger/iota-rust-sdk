// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Defines the [`MoveAuthenticatorArgs`] which represents a call to an
//! authenticator function in move which can authorize a transaction as part of
//! Account Abstraction.

use iota_types::{MoveAuthenticator, Owner, Transaction, TypeTag};

use crate::{
    ClientMethods, PTBArgumentList, error::Error, types::MoveTypes, unresolved::InputKind,
};

/// A function call to authorize a transaction via move.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct MoveAuthenticatorArgs {
    /// Input objects or primitive values
    pub call_args: Vec<InputKind>,
    /// Type arguments for the Move authenticate function
    pub type_args: Vec<TypeTag>,
}

impl MoveAuthenticatorArgs {
    /// Create a new move authenticator call with the function inputs.
    pub fn inputs<I: PTBArgumentList>(call_args: I) -> MoveAuthenticatorArgs {
        MoveAuthenticatorArgs {
            call_args: call_args.inputs(),
            type_args: Default::default(),
        }
    }

    /// Set the move authenticator call type parameters.
    pub fn generics<G: MoveTypes>(self) -> MoveAuthenticatorArgs {
        MoveAuthenticatorArgs {
            call_args: self.call_args,
            type_args: G::type_tags(),
        }
    }

    /// Set the move authenticator call type parameters manually.
    pub fn type_tags(self, tags: impl IntoIterator<Item = TypeTag>) -> MoveAuthenticatorArgs {
        MoveAuthenticatorArgs {
            call_args: self.call_args,
            type_args: tags.into_iter().collect(),
        }
    }

    /// Resolve this move authenticator call into a [`MoveAuthenticator`] which
    /// can be used to execute the given transaction (using a
    /// [`UserSignature::MoveAuthenticator`](iota_crypto::UserSignature::MoveAuthenticator)).
    pub async fn resolve(
        self,
        tx: &Transaction,
        client: &(impl ClientMethods + ?Sized),
    ) -> Result<MoveAuthenticator, Error> {
        let account = client
            .object(tx.as_v1().sender.into(), None)
            .await
            .map_err(Error::client)?
            .ok_or_else(|| Error::Input(format!("missing account {}", tx.as_v1().sender)))?;

        let mut call_args = Vec::new();
        for input in self.call_args {
            call_args.push(match input {
                InputKind::ImmutableOrOwned(object_id) => {
                    let obj = client
                        .object(object_id, None)
                        .await
                        .map_err(Error::client)?
                        .ok_or_else(|| Error::Input(format!("missing object {object_id}")))?;
                    iota_types::Input::ImmutableOrOwned(obj.object_ref())
                }
                InputKind::Shared { object_id, mutable } => {
                    let obj = client
                        .object(object_id, None)
                        .await
                        .map_err(Error::client)?
                        .ok_or_else(|| Error::Input(format!("missing object {object_id}")))?;

                    match obj.owner() {
                        Owner::Shared(version) => iota_types::Input::Shared {
                            object_id,
                            initial_shared_version: *version,
                            mutable,
                        },
                        _ => {
                            return Err(Error::InvalidMoveAuthArg(format!(
                                "object {object_id} was passed as shared, but is not"
                            )));
                        }
                    }
                }
                InputKind::Receiving(_) => {
                    return Err(Error::InvalidMoveAuthArg(
                        "call arguments must not be receiving".to_owned(),
                    ));
                }
                InputKind::Input(input) => input.clone(),
            })
        }
        Ok(match account.owner() {
            Owner::Immutable => {
                MoveAuthenticator::new_immutable(call_args, self.type_args, account.object_ref())
            }
            Owner::Shared(version) => MoveAuthenticator::new_shared(
                call_args,
                self.type_args,
                account.object_id(),
                *version,
            ),
            _ => {
                return Err(Error::InvalidMoveAuthAccount(
                    "account must be immutable or shared".to_owned(),
                ));
            }
        })
    }
}
