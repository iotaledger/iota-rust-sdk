// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::error::Result;

/// A 32-byte Blake2b256 hash output.
///
/// # BCS
///
/// A `Digest`'s BCS serialized form is defined by the following:
///
/// ```text
/// digest = %d32 32OCTET
/// ```
///
/// Due to historical reasons, even though a `Digest` has a fixed-length of 32,
/// IOTA's binary representation of a `Digest` is prefixed with its length
/// meaning its serialized binary form (in bcs) is 33 bytes long vs a more
/// compact 32 bytes.
#[derive(
    Debug,
    derive_more::Deref,
    derive_more::Display,
    derive_more::From,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    uniffi::Object,
)]
#[uniffi::export(Debug, Display, Hash, Eq)]
pub struct Digest(pub iota_sdk::types::Digest);

#[uniffi::export]
impl Digest {
    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        Ok(Self(iota_sdk::types::Digest::from_bytes(bytes)?))
    }

    #[uniffi::constructor]
    pub fn from_base58(base58: &str) -> Result<Self> {
        Ok(Self(iota_sdk::types::Digest::from_base58(base58)?))
    }

    #[uniffi::constructor]
    pub fn random() -> Self {
        Self(iota_sdk::types::Digest::random())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    pub fn to_base58(&self) -> String {
        self.0.to_base58()
    }

    /// Returns the next digest in byte-increasing order.
    pub fn next_lexicographical(&self) -> Self {
        Self(self.0.next_lexicographical())
    }

    /// Returns the next digest in byte-increasing order, or `None` if the
    /// result would overflow.
    pub fn next_lexicographical_opt(&self) -> Option<Arc<Self>> {
        self.0.next_lexicographical_opt().map(Self).map(Arc::new)
    }

    /// Returns whether the digest represents an object that is neither deleted
    /// nor wrapped
    pub fn is_object_alive(&self) -> bool {
        self.0.is_object_alive()
    }

    /// Returns whether the digest represents a deleted object
    pub fn is_object_deleted(&self) -> bool {
        self.0.is_object_deleted()
    }

    /// Returns whether the digest represents an object wrapped in another
    /// object.
    pub fn is_object_wrapped(&self) -> bool {
        self.0.is_object_wrapped()
    }
}

crate::export_iota_types_objects_bcs_conversion!(Digest);
crate::export_iota_types_objects_json_conversion!(Digest);
