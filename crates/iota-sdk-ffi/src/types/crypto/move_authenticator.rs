// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::types::{
    address::Address,
    digest::Digest,
    object::{ObjectId, ObjectReference},
    transaction::Input,
    type_tag::TypeTag,
};

/// MoveAuthenticator is a signature variant that enables a new
/// method of authentication through Move code.
/// This function represents the data received by the Move authenticate function
/// during the Account Abstraction authentication flow.
#[derive(derive_more::From, uniffi::Object)]
pub struct MoveAuthenticator(pub iota_sdk::types::MoveAuthenticator);

#[uniffi::export]
impl MoveAuthenticator {
    #[uniffi::constructor]
    pub fn new_immutable_or_owned(
        inputs: Vec<Arc<Input>>,
        type_arguments: Vec<Arc<TypeTag>>,
        object_to_authenticate: ObjectReference,
    ) -> Self {
        Self(iota_sdk::types::MoveAuthenticator::new_immutable_or_owned(
            inputs.into_iter().map(|v| v.0.clone()).collect(),
            type_arguments.into_iter().map(|v| v.0.clone()).collect(),
            object_to_authenticate.into(),
        ))
    }

    #[uniffi::constructor]
    pub fn new_immutable_shared(
        inputs: Vec<Arc<Input>>,
        type_arguments: Vec<Arc<TypeTag>>,
        object_to_authenticate: &ObjectId,
        initial_shared_version: u64,
    ) -> Self {
        Self(iota_sdk::types::MoveAuthenticator::new_immutable_shared(
            inputs.into_iter().map(|v| v.0.clone()).collect(),
            type_arguments.into_iter().map(|v| v.0.clone()).collect(),
            **object_to_authenticate,
            initial_shared_version,
        ))
    }

    pub fn address(&self) -> Address {
        self.0.address().into()
    }

    pub fn digest(&self) -> Digest {
        self.0.digest().into()
    }

    pub fn inputs(&self) -> Vec<Arc<Input>> {
        self.0
            .inputs()
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }

    pub fn type_arguments(&self) -> Vec<Arc<TypeTag>> {
        self.0
            .type_arguments()
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
