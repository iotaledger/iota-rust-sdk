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
/// public-key = %d00 ed25519-public-key /
///              %d01 secp256k1-public-key /
///              %d02 secp256r1-public-key /
///              %d04 passkey-public-key
/// ```
///
/// The gap in the flag values is intentional, as not all signature scheme
/// support public keys.
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
///                      (passkey-flag passkey-public-key)
/// ```
#[derive(Clone, Debug, derive_more::From, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[non_exhaustive]
pub enum PublicKey {
    Ed25519(Ed25519PublicKey),
    Secp256k1(Secp256k1PublicKey),
    Secp256r1(Secp256r1PublicKey),
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
            PublicKey::Passkey(pk) => pk.scheme(),
        }
    }

    /// Encode this public key as a base64 string of its scheme-flagged byte
    /// representation
    pub fn to_base64(&self) -> String {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend_from_slice(&[self.scheme() as u8]);
        bytes.extend_from_slice(self.as_ref());

        Base64::encode_string(&bytes)
    }

    /// Decode a public key from a base64 string of its scheme-flagged byte
    /// representation
    pub fn from_base64(s: &str) -> Result<Self, PublicKeyError> {
        let bytes = Base64::decode_vec(s)?;

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
                SignatureScheme::PasskeyAuthenticator => {
                    let pk = PasskeyPublicKey::new(Secp256r1PublicKey::from_bytes(tail)?);
                    Ok(Self::Passkey(pk))
                }
                _ => Err(PublicKeyError::InvalidInput),
            },
            None => Err(PublicKeyError::InvalidInput),
        }
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
            Self::Passkey(pk) => pk.as_ref(),
        }
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization {
    use std::str::FromStr;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;
    use crate::{Ed25519PublicKey, PasskeyPublicKey, Secp256k1PublicKey, Secp256r1PublicKey};

    /// Flat wire shape for `PublicKey`.
    ///
    /// The BCS variant tags are `PublicKey`'s own historical flag values
    /// (0x00 Ed25519, 0x01 Secp256k1, 0x02 Secp256r1, 0x04 Passkey) — note
    /// that passkey public keys use tag `0x04` here even though the passkey
    /// *signature scheme* flag is `0x06`. The `ZkLoginDeprecated` placeholder
    /// holds the `0x03` slot and is rejected by the deserializer.
    #[derive(Deserialize, Serialize)]
    #[cfg_attr(
        feature = "bcs-schema",
        derive(iota_bcs_schema::BcsSchema),
        bcs_schema(name = "public-key")
    )]
    enum PublicKeyBody {
        Ed25519(Ed25519PublicKey),
        Secp256k1(Secp256k1PublicKey),
        Secp256r1(Secp256r1PublicKey),
        #[cfg_attr(feature = "bcs-schema", bcs_schema(skip))]
        ZkLoginDeprecated,
        Passkey(PasskeyPublicKey),
    }

    #[derive(Deserialize, Serialize)]
    #[serde(tag = "scheme", rename_all = "lowercase")]
    #[serde(rename = "PublicKey")]
    enum ReadablePublicKey {
        Ed25519 { public_key: Ed25519PublicKey },
        Secp256k1 { public_key: Secp256k1PublicKey },
        Secp256r1 { public_key: Secp256r1PublicKey },
        ZkLoginDeprecated,
        Passkey { public_key: PasskeyPublicKey },
    }

    impl Serialize for PublicKey {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = match self {
                    PublicKey::Ed25519(public_key) => ReadablePublicKey::Ed25519 {
                        public_key: *public_key,
                    },
                    PublicKey::Secp256k1(public_key) => ReadablePublicKey::Secp256k1 {
                        public_key: *public_key,
                    },
                    PublicKey::Secp256r1(public_key) => ReadablePublicKey::Secp256r1 {
                        public_key: *public_key,
                    },
                    PublicKey::Passkey(public_key) => ReadablePublicKey::Passkey {
                        public_key: public_key.clone(),
                    },
                };
                readable.serialize(serializer)
            } else {
                let body = match self {
                    PublicKey::Ed25519(public_key) => PublicKeyBody::Ed25519(*public_key),
                    PublicKey::Secp256k1(public_key) => PublicKeyBody::Secp256k1(*public_key),
                    PublicKey::Secp256r1(public_key) => PublicKeyBody::Secp256r1(*public_key),
                    PublicKey::Passkey(public_key) => PublicKeyBody::Passkey(public_key.clone()),
                };
                body.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for PublicKey {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let readable = ReadablePublicKey::deserialize(deserializer)?;
                Ok(match readable {
                    ReadablePublicKey::Ed25519 { public_key } => Self::Ed25519(public_key),
                    ReadablePublicKey::Secp256k1 { public_key } => Self::Secp256k1(public_key),
                    ReadablePublicKey::Secp256r1 { public_key } => Self::Secp256r1(public_key),
                    ReadablePublicKey::ZkLoginDeprecated => {
                        return Err(serde::de::Error::custom(
                            "zkLoginDeprecated is not supported",
                        ));
                    }
                    ReadablePublicKey::Passkey { public_key } => Self::Passkey(public_key),
                })
            } else {
                let body = PublicKeyBody::deserialize(deserializer)?;
                Ok(match body {
                    PublicKeyBody::Ed25519(public_key) => Self::Ed25519(public_key),
                    PublicKeyBody::Secp256k1(public_key) => Self::Secp256k1(public_key),
                    PublicKeyBody::Secp256r1(public_key) => Self::Secp256r1(public_key),
                    PublicKeyBody::ZkLoginDeprecated => {
                        return Err(serde::de::Error::custom(
                            "zkLoginDeprecated is not supported",
                        ));
                    }
                    PublicKeyBody::Passkey(public_key) => Self::Passkey(public_key),
                })
            }
        }
    }

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

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;
    use crate::UserSignature;

    /// The passkey tag in the `PublicKey` BCS enum must be
    /// `0x04`. Locking this in here guards against accidental reordering,
    /// since the tag is part of the on-chain wire format.
    #[test]
    fn passkey_member_public_key_bcs_tag() {
        let passkey_b64 = "BiVYDmenOnqS+thmz5m5SrZnWaKXZLVxgh+rri6LHXs25B0AAAAAnQF7InR5cGUiOiJ3ZWJhdXRobi5nZXQiLCAiY2hhbGxlbmdlIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTE3MyIsImNyb3NzT3JpZ2luIjpmYWxzZSwgInVua25vd24iOiAidW5rbm93biJ9YgJMwqcOmZI7F/N+K5SMe4DRYCb4/cDWW68SFneSHoD2GxKKhksbpZ5rZpdrjSYABTCsFQQBpLORzTvbj4edWKd/AsEBeovrGvHR9Ku7critg6k7qvfFlPUngujXfEzXd8Eg";
        let UserSignature::PasskeyAuthenticator(passkey_authenticator) =
            UserSignature::from_base64(passkey_b64).unwrap()
        else {
            panic!("expected passkey authenticator");
        };

        let pk = PublicKey::Passkey(passkey_authenticator.public_key());
        let bcs_bytes = bcs::to_bytes(&pk).unwrap();
        assert_eq!(bcs_bytes[0], 0x04, "passkey must use BCS tag 0x04");
        // 1 tag byte + 33 bytes for the secp256r1 compressed public key.
        assert_eq!(bcs_bytes.len(), 34);
    }
}
