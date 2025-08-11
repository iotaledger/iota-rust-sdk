// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::error::Result;

macro_rules! impl_digest_wrapper {
    ($(#[$meta:meta])* $t:ident) => {
        $(#[$meta])*
        #[derive(
            Copy,
            Clone,
            Debug,
            Default,
            Hash,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            derive_more::From,
            derive_more::Deref,
            uniffi::Object,
        )]
        pub struct $t(pub iota_types::$t);

        #[uniffi::export]
        impl $t {
            #[uniffi::constructor]
            pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
                Ok(Self(iota_types::$t::from_bytes(bytes)?))
            }

            #[uniffi::constructor]
            pub fn from_base58(base58: &str) -> Result<Self> {
                Ok(Self(iota_types::$t::from_base58(base58)?))
            }

            #[uniffi::constructor]
            pub fn generate() -> Self {
                let mut rng = rand::thread_rng();
                Self(iota_types::$t::generate(&mut rng))
            }

            pub fn to_bytes(&self) -> Vec<u8> {
                self.0.as_bytes().to_vec()
            }

            pub fn to_base58(&self) -> String {
                self.0.to_base58()
            }
        }

        impl From<&iota_types::$t> for $t {
            fn from(value: &iota_types::$t) -> Self {
                Self(*value)
            }
        }
    };
}

impl_digest_wrapper!(
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
    Digest
);
impl_digest_wrapper!(CheckpointDigest);
impl_digest_wrapper!(CheckpointContentsDigest);
impl_digest_wrapper!(TransactionDigest);
impl_digest_wrapper!(TransactionEffectsDigest);
impl_digest_wrapper!(TransactionEventsDigest);
impl_digest_wrapper!(ObjectDigest);
impl_digest_wrapper!(ConsensusCommitDigest);
impl_digest_wrapper!(EffectsAuxiliaryDataDigest);
