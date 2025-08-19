// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub mod multisig;
pub mod passkey;
pub mod simple;
pub mod validator;
pub mod zklogin;

use std::sync::Arc;

use crate::{error::Result, types::signature::SimpleSignature};

macro_rules! impl_crypto_object {
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

impl_crypto_object!(
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
impl_crypto_object!(
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
impl_crypto_object!(
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
impl_crypto_object!(
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
impl_crypto_object!(
    /// An ed25519 signature.
    ///
    /// # BCS
    ///
    /// The BCS serialized form for this type is defined by the following ABNF:
    ///
    /// ```text
    /// ed25519-signature = 64OCTECT
    /// ```
    Ed25519Signature
);
impl_crypto_object!(
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
    Bls12381Signature
);
impl_crypto_object!(
    /// A secp256k1 public key.
    ///
    /// # BCS
    ///
    /// The BCS serialized form for this type is defined by the following ABNF:
    ///
    /// ```text
    /// secp256k1-public-key = 33OCTECT
    /// ```
    Secp256k1Signature
);
impl_crypto_object!(
    /// A secp256r1 public key.
    ///
    /// # BCS
    ///
    /// The BCS serialized form for this type is defined by the following ABNF:
    ///
    /// ```text
    /// secp256r1-public-key = 33OCTECT
    /// ```
    Secp256r1Signature
);
