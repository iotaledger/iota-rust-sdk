// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::error::Result;

/// A member of a Validator Committee
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// validator-committee-member = bls-public-key
///                              u64 ; stake
/// ```
#[derive(Clone, Debug, uniffi::Record)]
pub struct ValidatorCommitteeMember {
    pub public_key: Arc<Bls12381PublicKey>,
    pub stake: u64,
}

impl From<iota_types::ValidatorCommitteeMember> for ValidatorCommitteeMember {
    fn from(value: iota_types::ValidatorCommitteeMember) -> Self {
        Self {
            public_key: Arc::new(value.public_key.into()),
            stake: value.stake,
        }
    }
}

impl From<ValidatorCommitteeMember> for iota_types::ValidatorCommitteeMember {
    fn from(value: ValidatorCommitteeMember) -> Self {
        Self {
            public_key: **value.public_key,
            stake: value.stake,
        }
    }
}

macro_rules! impl_public_key {
    ($(#[$meta:meta])* $t:ident) => {
        $(#[$meta])*
        #[derive(Copy, Clone, Debug, derive_more::From, derive_more::Deref, uniffi::Object)]
        pub struct $t(pub iota_types::$t);

        #[uniffi::export]
        impl $t {
            #[uniffi::constructor]
            pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
                Ok(Self(iota_types::$t::from_bytes(bytes)?))
            }

            #[uniffi::constructor]
            pub fn from_str(s: &str) -> Result<Self> {
                Ok(Self(std::str::FromStr::from_str(s)?))
            }

            #[uniffi::constructor]
            pub fn generate() -> Self {
                let mut rng = rand::thread_rng();
                Self(iota_types::$t::generate(&mut rng))
            }

            pub fn to_bytes(&self) -> Vec<u8> {
                self.0.as_bytes().to_vec()
            }
        }
    };
}

impl_public_key!(
    /// A bls12381 min-sig public key.
    ///
    /// # BCS
    ///
    /// The BCS serialized form for this type is defined by the following ABNF:
    ///
    /// ```text
    /// bls-public-key = %x60 96OCTECT
    /// ```
    ///
    /// Due to historical reasons, even though a min-sig `Bls12381PublicKey` has a
    /// fixed-length of 96, IOTA's binary representation of a min-sig
    /// `Bls12381PublicKey` is prefixed with its length meaning its serialized
    /// binary form (in bcs) is 97 bytes long vs a more compact 96 bytes.
    Bls12381PublicKey
);
impl_public_key!(
    /// An ed25519 public key.
    ///
    /// # BCS
    ///
    /// The BCS serialized form for this type is defined by the following ABNF:
    ///
    /// ```text
    /// ed25519-public-key = 32OCTECT
    /// ```
    Ed25519PublicKey
);
impl_public_key!(
    /// A secp256k1 signature.
    ///
    /// # BCS
    ///
    /// The BCS serialized form for this type is defined by the following ABNF:
    ///
    /// ```text
    /// secp256k1-signature = 64OCTECT
    /// ```
    Secp256k1PublicKey
);
impl_public_key!(
    /// A secp256r1 signature.
    ///
    /// # BCS
    ///
    /// The BCS serialized form for this type is defined by the following ABNF:
    ///
    /// ```text
    /// secp256r1-signature = 64OCTECT
    /// ```
    Secp256r1PublicKey
);
