// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{convert::Infallible, str::FromStr};

use base64ct::{Base64, Encoding};

use super::{
    Ed25519PublicKey, PublicKeyExt, Secp256k1PublicKey, Secp256r1PublicKey, SignatureScheme,
    passkey::PasskeyPublicKey,
};
use crate::Address;

// TODO adapt comment
/// Enum of valid public keys for multisig committee members
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// multisig-member-public-key = ed25519-multisig-member-public-key /
///                              secp256k1-multisig-member-public-key /
///                              secp256r1-multisig-member-public-key /
///                              zklogin-multisig-member-public-key-deprecated /
///                              passkey-multisig-member-public-key
///
/// ed25519-multisig-member-public-key              = %d00 ed25519-public-key
/// secp256k1-multisig-member-public-key            = %d01 secp256k1-public-key
/// secp256r1-multisig-member-public-key            = %d02 secp256r1-public-key
/// zklogin-multisig-member-public-key-deprecated   = %d03
/// passkey-multisig-member-public-key              = %d04 passkey-public-key
/// ```
///
/// There is also a legacy encoding for this type defined as:
///
/// ```text
/// legacy-multisig-member-public-key = string ; which is valid base64 encoded
///                                            ; and the decoded bytes are defined
///                                            ; by legacy-public-key
/// legacy-public-key = (ed25519-flag ed25519-public-key) /
///                     (secp256k1-flag secp256k1-public-key) /
///                     (secp256r1-flag secp256r1-public-key)
/// ```
#[derive(Clone, Debug, PartialEq, Eq, derive_more::From)]
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

    pub fn scheme(&self) -> SignatureScheme {
        match self {
            PublicKey::Ed25519(ed25519_public_key) => ed25519_public_key.scheme(),
            PublicKey::Secp256k1(secp256k1_public_key) => secp256k1_public_key.scheme(),
            PublicKey::Secp256r1(secp256r1_public_key) => secp256r1_public_key.scheme(),
            PublicKey::ZkLoginDeprecated => SignatureScheme::ZkLoginAuthenticatorDeprecated,
            PublicKey::Passkey(passkey_public_key) => passkey_public_key.scheme(),
        }
    }

    pub fn to_base64(&self) -> String {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&[self.scheme() as u8]);
        bytes.extend_from_slice(self.as_ref());
        base64ct::Base64::encode_string(&bytes)
    }

    // TODO infallible
    pub fn from_base64(s: &str) -> Result<Self, Infallible> {
        let bytes = Base64::decode_vec(s).unwrap();

        match bytes.first() {
            Some(x) => {
                if x == &(SignatureScheme::Ed25519 as u8) {
                    let pk = Ed25519PublicKey::from_bytes(&bytes[1..]).unwrap();
                    Ok(Self::Ed25519(pk))
                } else if x == &(SignatureScheme::Secp256k1 as u8) {
                    let pk = Secp256k1PublicKey::from_bytes(&bytes[1..]).unwrap();
                    Ok(Self::Secp256k1(pk))
                } else if x == &(SignatureScheme::Secp256r1 as u8) {
                    let pk = Secp256r1PublicKey::from_bytes(&bytes[1..]).unwrap();
                    Ok(Self::Secp256r1(pk))
                } else if x == &(SignatureScheme::PasskeyAuthenticator as u8) {
                    let pk =
                        PasskeyPublicKey::new(Secp256r1PublicKey::from_bytes(&bytes[1..]).unwrap());
                    Ok(Self::Passkey(pk))
                } else {
                    panic!()
                    // Err(FastCryptoError::InvalidInput)
                }
            }
            _ => panic!(),
            // _ => Err(FastCryptoError::InvalidInput),
        }
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

impl From<&PublicKey> for Address {
    fn from(pk: &PublicKey) -> Self {
        pk.derive_address()
    }
}

impl FromStr for PublicKey {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_base64(s)
    }
}
