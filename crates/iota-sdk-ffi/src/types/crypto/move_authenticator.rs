// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::types::{
    address::Address,
    move_core::TypeTag,
    object::ObjectReference,
    transaction::{Input, SharedObjectReference},
};

/// MoveAuthenticator is a signature variant that enables a method of
/// authentication through Move code. This type represents the data received
/// by the Move authenticate function during the Account Abstraction
/// authentication flow.
#[derive(Debug, derive_more::From, uniffi::Object)]
pub struct MoveAuthenticator(pub iota_sdk::types::MoveAuthenticator);

#[uniffi::export]
impl MoveAuthenticator {
    #[uniffi::constructor]
    pub fn new_v1(move_authenticator_v1: &MoveAuthenticatorV1) -> Self {
        Self(iota_sdk::types::MoveAuthenticator::V1(
            move_authenticator_v1.0.clone(),
        ))
    }

    /// Convert this move authenticator into a version 1 move authenticator if
    /// it is one, or panic otherwise
    pub fn as_v1(&self) -> Arc<MoveAuthenticatorV1> {
        Arc::new(MoveAuthenticatorV1(self.0.as_v1().clone()))
    }
}

/// Version 1 of the [`MoveAuthenticator`].
#[derive(Debug, derive_more::From, uniffi::Object)]
pub struct MoveAuthenticatorV1(pub iota_sdk::types::MoveAuthenticatorV1);

#[uniffi::export]
impl MoveAuthenticatorV1 {
    /// Create a new move authenticator with an immutable object.
    #[uniffi::constructor]
    pub fn new_with_immutable_account_object(
        call_args: Vec<Input>,
        type_args: Vec<Arc<TypeTag>>,
        object_to_authenticate: ObjectReference,
    ) -> Self {
        Self(
            iota_sdk::types::MoveAuthenticatorV1::new_with_immutable_account_object(
                call_args.into_iter().map(Into::into).collect(),
                type_args.into_iter().map(|v| v.0.clone()).collect(),
                object_to_authenticate.into(),
            ),
        )
    }

    /// Create a new move authenticator with a shared object.
    #[uniffi::constructor]
    pub fn new_with_shared_account_object(
        call_args: Vec<Input>,
        type_args: Vec<Arc<TypeTag>>,
        object_to_authenticate: SharedObjectReference,
    ) -> Self {
        Self(
            iota_sdk::types::MoveAuthenticatorV1::new_with_shared_account_object(
                call_args.into_iter().map(Into::into).collect(),
                type_args.into_iter().map(|v| v.0.clone()).collect(),
                object_to_authenticate.into(),
            ),
        )
    }

    pub fn address(&self) -> Address {
        self.0.address().into()
    }

    pub fn call_args(&self) -> Vec<Input> {
        self.0.call_args().iter().cloned().map(Into::into).collect()
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
