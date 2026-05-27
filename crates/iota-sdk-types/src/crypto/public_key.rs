// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use base64ct::{Base64, Encoding};

use super::{
    Ed25519PublicKey, PublicKeyExt, Secp256k1PublicKey, Secp256r1PublicKey, SignatureScheme,
    passkey::{PasskeyAuthenticator, PasskeyPublicKey},
    signature::InvalidSignatureScheme,
};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PublicKeyError {
    #[error("{0}")]
    Base64(#[from] base64ct::Error),
    #[error("{0}")]
    TryFromSlice(#[from] std::array::TryFromSliceError),
    #[error("Invalid input")]
    InvalidInput,
    #[error("{0}")]
    InvalidSignatureScheme(#[from] InvalidSignatureScheme),
}

/// Enum of valid public keys for the signature schemes supported by IOTA.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// public-key = ed25519-public-key-variant /
///              secp256k1-public-key-variant /
///              secp256r1-public-key-variant /
///              zklogin-public-key-variant-deprecated /
///              passkey-public-key-variant
///
/// ed25519-public-key-variant              = %d00 ed25519-public-key
/// secp256k1-public-key-variant            = %d01 secp256k1-public-key
/// secp256r1-public-key-variant            = %d02 secp256r1-public-key
/// zklogin-public-key-variant-deprecated   = %d03
/// passkey-public-key-variant              = %d04 passkey-public-key
/// ```
///
/// There is also a base64 encoding for this type, used by [`Self::to_base64`]
/// and [`Self::from_base64`], defined as:
///
/// ```text
/// base64-public-key = string ; which is valid base64 encoded
///                            ; and the decoded bytes are defined
///                            ; by flagged-public-key
/// flagged-public-key = (ed25519-flag ed25519-public-key) /
///                      (secp256k1-flag secp256k1-public-key) /
///                      (secp256r1-flag secp256r1-public-key) /
///                      (zklogin-flag-deprecated) /
///                      (passkey-flag passkey-public-key)
/// ```
#[derive(Clone, Debug, derive_more::From, Eq, PartialEq)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[non_exhaustive]
pub enum PublicKey {
    Ed25519(Ed25519PublicKey),
    Secp256k1(Secp256k1PublicKey),
    Secp256r1(Secp256r1PublicKey),
    ZkLoginDeprecated,
    Passkey(PasskeyPublicKey),
}

impl PublicKey {
    crate::def_is_as_into_opt!(
        Ed25519(Ed25519PublicKey),
        Secp256k1(Secp256k1PublicKey),
        Secp256r1(Secp256r1PublicKey),
        Passkey(PasskeyPublicKey),
    );

    /// Return the flag for this signature scheme
    pub fn scheme(&self) -> SignatureScheme {
        match self {
            PublicKey::Ed25519(pk) => pk.scheme(),
            PublicKey::Secp256k1(pk) => pk.scheme(),
            PublicKey::Secp256r1(pk) => pk.scheme(),
            PublicKey::ZkLoginDeprecated => SignatureScheme::ZkLoginAuthenticatorDeprecated,
            PublicKey::Passkey(pk) => pk.scheme(),
        }
    }

    /// Encode this public key as the scheme flag byte followed by the raw key
    /// bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&[self.scheme() as u8]);
        bytes.extend_from_slice(self.as_ref());
        bytes
    }

    /// Decode a public key from its scheme-flagged byte representation
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, PublicKeyError> {
        let bytes = bytes.as_ref();

        match bytes.split_first() {
            Some((flag, tail)) => match SignatureScheme::from_byte(*flag)? {
                SignatureScheme::Ed25519 => {
                    let pk = Ed25519PublicKey::from_bytes(tail)?;
                    Ok(Self::Ed25519(pk))
                }
                SignatureScheme::Secp256k1 => {
                    let pk = Secp256k1PublicKey::from_bytes(tail)?;
                    Ok(Self::Secp256k1(pk))
                }
                SignatureScheme::Secp256r1 => {
                    let pk = Secp256r1PublicKey::from_bytes(tail)?;
                    Ok(Self::Secp256r1(pk))
                }
                SignatureScheme::ZkLoginAuthenticatorDeprecated => Ok(Self::ZkLoginDeprecated),
                SignatureScheme::PasskeyAuthenticator => {
                    let pk = PasskeyPublicKey::new(Secp256r1PublicKey::from_bytes(tail)?);
                    Ok(Self::Passkey(pk))
                }
                _ => Err(PublicKeyError::InvalidInput),
            },
            None => Err(PublicKeyError::InvalidInput),
        }
    }

    /// Encode this public key as a base64 string of its scheme-flagged byte
    /// representation
    pub fn to_base64(&self) -> String {
        Base64::encode_string(&self.to_bytes())
    }

    /// Decode a public key from a base64 string of its scheme-flagged byte
    /// representation
    pub fn from_base64(s: &str) -> Result<Self, PublicKeyError> {
        Self::from_bytes(&Base64::decode_vec(s)?)
    }
}

impl From<PasskeyAuthenticator> for PublicKey {
    fn from(passkey_authenticator: PasskeyAuthenticator) -> Self {
        Self::Passkey(passkey_authenticator.public_key())
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Ed25519(pk) => pk.as_ref(),
            Self::Secp256k1(pk) => pk.as_ref(),
            Self::Secp256r1(pk) => pk.as_ref(),
            Self::ZkLoginDeprecated => &[],
            Self::Passkey(pk) => pk.as_ref(),
        }
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization {
    use std::str::FromStr;

    use super::*;

    #[cfg(feature = "hash")]
    impl From<&PublicKey> for crate::Address {
        fn from(pk: &PublicKey) -> Self {
            pk.derive_address()
        }
    }

    impl FromStr for PublicKey {
        type Err = PublicKeyError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Self::from_base64(s)
        }
    }
}
