// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::types::{
    digest::ObjectDigest,
    object::{Object, ObjectId},
};

/// A potentially unresolved transaction input. Note that one can construct a
/// fully resolved input using the provided constructors, but this struct is
/// also useful when the input data is not complete.
///
/// If used in the context of transaction builder, make sure to call
/// `tx.resolve` function on the transaction builder to resolve all unresolved
/// inputs.
#[derive(derive_more::From, uniffi::Object)]
pub struct UnresolvedInput(pub iota_transaction_builder::unresolved::Input);

#[uniffi::export]
impl UnresolvedInput {
    #[uniffi::constructor]
    pub fn from_object(object: &Object) -> Self {
        Self(iota_transaction_builder::unresolved::Input::from(&object.0))
    }

    #[uniffi::constructor]
    pub fn from_object_id(object_id: &ObjectId) -> Self {
        Self(iota_transaction_builder::unresolved::Input::from(
            **object_id,
        ))
    }

    /// Return an owned kind of object with all required fields.
    #[uniffi::constructor]
    pub fn new_owned(object_id: &ObjectId, version: u64, digest: &ObjectDigest) -> Self {
        Self(iota_transaction_builder::unresolved::Input::owned(
            **object_id,
            version,
            **digest,
        ))
    }

    /// Return an immutable kind of object with all required fields.
    #[uniffi::constructor]
    pub fn new_immutable(object_id: &ObjectId, version: u64, digest: &ObjectDigest) -> Self {
        Self(iota_transaction_builder::unresolved::Input::immutable(
            **object_id,
            version,
            **digest,
        ))
    }

    /// Return a receiving kind of object with all required fields.
    #[uniffi::constructor]
    pub fn new_receiving(object_id: &ObjectId, version: u64, digest: &ObjectDigest) -> Self {
        Self(iota_transaction_builder::unresolved::Input::receiving(
            **object_id,
            version,
            **digest,
        ))
    }

    /// Return a shared object.
    /// - `mutable` controls whether a command can accept the object by value or
    ///   mutable reference.
    /// - `initial_shared_version` is the first version the object was shared
    ///   at.
    #[uniffi::constructor]
    pub fn new_shared(object_id: &ObjectId, initial_shared_version: u64, mutable: bool) -> Self {
        Self(iota_transaction_builder::unresolved::Input::shared(
            **object_id,
            initial_shared_version,
            mutable,
        ))
    }

    /// Return an object with only its unique identifier.
    #[uniffi::constructor]
    pub fn by_id(object_id: &ObjectId) -> Self {
        Self(iota_transaction_builder::unresolved::Input::by_id(
            **object_id,
        ))
    }

    /// Set the object kind to immutable.
    pub fn with_immutable_kind(&self) -> Self {
        Self(self.0.clone().with_immutable_kind())
    }

    /// Set the object kind to owned.
    pub fn with_owned_kind(&self) -> Self {
        Self(self.0.clone().with_owned_kind())
    }

    /// Set the object kind to receiving.
    pub fn with_receiving_kind(&self) -> Self {
        Self(self.0.clone().with_receiving_kind())
    }

    /// Set the object kind to shared.
    pub fn with_shared_kind(&self) -> Self {
        Self(self.0.clone().with_shared_kind())
    }

    /// Set the specified version.
    pub fn with_version(&self, version: u64) -> Self {
        Self(self.0.clone().with_version(version))
    }

    /// Set the specified digest.
    pub fn with_digest(&self, digest: &ObjectDigest) -> Self {
        Self(self.0.clone().with_digest(**digest))
    }

    // Shared fields

    /// Set the initial shared version.
    pub fn with_initial_shared_version(&self, initial_version: u64) -> Self {
        Self(self.0.clone().with_initial_shared_version(initial_version))
    }

    /// Make the object shared and set `mutable` to true when the input is used
    /// by value.
    pub fn by_val(&self) -> Self {
        Self(self.0.clone().by_val())
    }

    /// Make the object shared and set `mutable` to false when the input is used
    /// by reference.
    pub fn by_ref(&self) -> Self {
        Self(self.0.clone().by_ref())
    }

    /// Make the object shared and set `mutable` to true when the input is used
    /// by mutable reference.
    pub fn by_mut(&self) -> Self {
        Self(self.0.clone().by_mut())
    }
}
