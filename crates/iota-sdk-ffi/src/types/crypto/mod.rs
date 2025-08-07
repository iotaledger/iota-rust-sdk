// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub mod multisig;
pub mod zklogin;

use std::sync::Arc;

use crate::{error::Result, types::signature::SimpleSignature};

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

/// A passkey authenticator.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// passkey-bcs = bytes               ; where the contents of the bytes are
///                                   ; defined by <passkey>
/// passkey     = passkey-flag
///               bytes               ; passkey authenticator data
///               client-data-json    ; valid json
///               simple-signature    ; required to be a secp256r1 signature
///
/// client-data-json = string ; valid json
/// ```
///
/// See [CollectedClientData](https://www.w3.org/TR/webauthn-2/#dictdef-collectedclientdata) for
/// the required json-schema for the `client-data-json` rule. In addition, IOTA
/// currently requires that the `CollectedClientData.type` field is required to
/// be `webauthn.get`.
///
/// Note: Due to historical reasons, signatures are serialized slightly
/// different from the majority of the types in IOTA. In particular if a
/// signature is ever embedded in another structure it generally is serialized
/// as `bytes` meaning it has a length prefix that defines the length of
/// the completely serialized signature.
#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct PasskeyAuthenticator(pub iota_types::PasskeyAuthenticator);

#[uniffi::export]
impl PasskeyAuthenticator {
    /// Opaque authenticator data for this passkey signature.
    ///
    /// See [Authenticator Data](https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data) for
    /// more information on this field.
    pub fn authenticator_data(&self) -> Vec<u8> {
        self.0.authenticator_data().to_vec()
    }

    /// Structured, unparsed, JSON for this passkey signature.
    ///
    /// See [CollectedClientData](https://www.w3.org/TR/webauthn-2/#dictdef-collectedclientdata)
    /// for more information on this field.
    pub fn client_data_json(&self) -> String {
        self.0.client_data_json().to_owned()
    }

    /// The parsed challenge message for this passkey signature.
    ///
    /// This is parsed by decoding the base64url data from the
    /// `client_data_json.challenge` field.
    pub fn challenge(&self) -> Vec<u8> {
        self.0.challenge().to_vec()
    }

    /// The passkey signature.
    pub fn signature(&self) -> SimpleSignature {
        self.0.signature().into()
    }
}

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
