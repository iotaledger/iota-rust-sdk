// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::types::{
    address::Address,
    object::{ObjectId, ObjectReference},
    transaction::Input,
    type_tag::TypeTag,
    version::Version,
};

/// MoveAuthenticator is a signature variant that enables a method of
/// authentication through Move code. This type represents the data received
/// by the Move authenticate function during the Account Abstraction
/// authentication flow.
#[derive(Debug, derive_more::From, uniffi::Object)]
pub struct MoveAuthenticator(pub iota_sdk::types::MoveAuthenticator);

#[uniffi::export]
impl MoveAuthenticator {
    /// Create a new move authenticator from an immutable object.
    #[uniffi::constructor]
    pub fn new_immutable(
        call_args: Vec<Arc<Input>>,
        type_args: Vec<Arc<TypeTag>>,
        object_to_authenticate: ObjectReference,
    ) -> Self {
        Self(iota_sdk::types::MoveAuthenticator::new_immutable(
            call_args.into_iter().map(|v| v.0.clone()).collect(),
            type_args.into_iter().map(|v| v.0.clone()).collect(),
            object_to_authenticate.into(),
        ))
    }

    /// Create a new move authenticator from a shared object.
    #[uniffi::constructor]
    pub fn new_shared(
        call_args: Vec<Arc<Input>>,
        type_args: Vec<Arc<TypeTag>>,
        object_to_authenticate: &ObjectId,
        initial_shared_version: &Version,
    ) -> Self {
        Self(iota_sdk::types::MoveAuthenticator::new_shared(
            call_args.into_iter().map(|v| v.0.clone()).collect(),
            type_args.into_iter().map(|v| v.0.clone()).collect(),
            **object_to_authenticate,
            **initial_shared_version,
        ))
    }

    pub fn address(&self) -> Address {
        self.0.address().into()
    }

    pub fn call_args(&self) -> Vec<Arc<Input>> {
        self.0
            .call_args()
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }

    pub fn type_args(&self) -> Vec<Arc<TypeTag>> {
        self.0
            .type_args()
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }

    pub fn object_to_authenticate(&self) -> Input {
        self.0.object_to_authenticate().clone().into()
    }
}
