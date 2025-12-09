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
/// digest = %x20 32OCTET
/// ```
///
/// Due to historical reasons, even though a `Digest` has a fixed-length of 32,
/// IOTA's binary representation of a `Digest` is prefixed with its length
/// meaning its serialized binary form (in bcs) is 33 bytes long vs a more
/// compact 32 bytes.
#[derive(derive_more::From, derive_more::Deref, uniffi::Object)]
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
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        Self(iota_sdk::types::Digest::generate(&mut rng))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    pub fn to_base58(&self) -> String {
        self.0.to_base58()
    }

    /// Returns the next digest in byte-increasing order.
    pub fn next_lexicographical(&self) -> Self {
        self.0.next_lexicographical().into()
    }
}

crate::export_iota_types_objects_bcs_conversion!(Digest);
