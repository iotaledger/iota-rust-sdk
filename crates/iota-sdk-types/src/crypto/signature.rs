// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{
    Ed25519PublicKey, Ed25519Signature, MultisigAggregatedSignature, PasskeyAuthenticator,
    PublicKey, Secp256k1PublicKey, Secp256k1Signature, Secp256r1PublicKey, Secp256r1Signature,
};
use crate::crypto::move_authenticator::MoveAuthenticator;

/// A basic signature
///
/// This enumeration defines the set of simple or basic signature schemes
/// supported by IOTA. Most signature schemes supported by IOTA end up
/// comprising of at least one simple signature scheme.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// simple-signature-bcs = bytes ; where the contents of the bytes are defined by <simple-signature>
/// simple-signature = (ed25519-flag ed25519-signature ed25519-public-key) /
///                    (secp256k1-flag secp256k1-signature secp256k1-public-key) /
///                    (secp256r1-flag secp256r1-signature secp256r1-public-key)
/// ```
///
/// Note: Due to historical reasons, signatures are serialized slightly
/// different from the majority of the types in IOTA. In particular if a
/// signature is ever embedded in another structure it generally is serialized
/// as `bytes` meaning it has a length prefix that defines the length of
/// the completely serialized signature.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[non_exhaustive]
pub enum SimpleSignature {
    Ed25519 {
        signature: Ed25519Signature,
        public_key: Ed25519PublicKey,
    },
    Secp256k1 {
        signature: Secp256k1Signature,
        public_key: Secp256k1PublicKey,
    },
    Secp256r1 {
        signature: Secp256r1Signature,
        public_key: Secp256r1PublicKey,
    },
}

impl SimpleSignature {
    pub fn new_ed25519(signature: Ed25519Signature, public_key: Ed25519PublicKey) -> Self {
        Self::Ed25519 {
            signature,
            public_key,
        }
    }

    pub fn new_secp256k1(signature: Secp256k1Signature, public_key: Secp256k1PublicKey) -> Self {
        Self::Secp256k1 {
            signature,
            public_key,
        }
    }

    pub fn new_secp256r1(signature: Secp256r1Signature, public_key: Secp256r1PublicKey) -> Self {
        Self::Secp256r1 {
            signature,
            public_key,
        }
    }

    crate::def_is!(Ed25519, Secp256k1, Secp256r1);

    pub fn as_ed25519_sig_opt(&self) -> Option<&Ed25519Signature> {
        if let Self::Ed25519 { signature, .. } = self {
            Some(signature)
        } else {
            None
        }
    }

    pub fn as_ed25519_sig(&self) -> &Ed25519Signature {
        self.as_ed25519_sig_opt().expect("not an ed25519 signature")
    }

    pub fn as_ed25519_pub_key_opt(&self) -> Option<&Ed25519PublicKey> {
        if let Self::Ed25519 { public_key, .. } = self {
            Some(public_key)
        } else {
            None
        }
    }

    pub fn as_ed25519_pub_key(&self) -> &Ed25519PublicKey {
        self.as_ed25519_pub_key_opt()
            .expect("not an ed25519 public key")
    }

    pub fn into_ed25519_opt(self) -> Option<(Ed25519Signature, Ed25519PublicKey)> {
        if let Self::Ed25519 {
            signature,
            public_key,
            ..
        } = self
        {
            Some((signature, public_key))
        } else {
            None
        }
    }

    pub fn into_ed25519(self) -> (Ed25519Signature, Ed25519PublicKey) {
        self.into_ed25519_opt().expect("not an ed25519 signature")
    }

    pub fn as_secp256k1_sig_opt(&self) -> Option<&Secp256k1Signature> {
        if let Self::Secp256k1 { signature, .. } = self {
            Some(signature)
        } else {
            None
        }
    }

    pub fn as_secp256k1_sig(&self) -> &Secp256k1Signature {
        self.as_secp256k1_sig_opt()
            .expect("not an secp256k1 signature")
    }

    pub fn as_secp256k1_pub_key_opt(&self) -> Option<&Secp256k1PublicKey> {
        if let Self::Secp256k1 { public_key, .. } = self {
            Some(public_key)
        } else {
            None
        }
    }

    pub fn as_secp256k1_pub_key(&self) -> &Secp256k1PublicKey {
        self.as_secp256k1_pub_key_opt()
            .expect("not an secp256k1 public key")
    }

    pub fn into_secp256k1_opt(self) -> Option<(Secp256k1Signature, Secp256k1PublicKey)> {
        if let Self::Secp256k1 {
            signature,
            public_key,
            ..
        } = self
        {
            Some((signature, public_key))
        } else {
            None
        }
    }

    pub fn into_secp256k1(self) -> (Secp256k1Signature, Secp256k1PublicKey) {
        self.into_secp256k1_opt()
            .expect("not an secp256k1 signature")
    }

    pub fn as_secp256r1_sig_opt(&self) -> Option<&Secp256r1Signature> {
        if let Self::Secp256r1 { signature, .. } = self {
            Some(signature)
        } else {
            None
        }
    }

    pub fn as_secp256r1_sig(&self) -> &Secp256r1Signature {
        self.as_secp256r1_sig_opt()
            .expect("not an secp256r1 signature")
    }

    pub fn as_secp256r1_pub_key_opt(&self) -> Option<&Secp256r1PublicKey> {
        if let Self::Secp256r1 { public_key, .. } = self {
            Some(public_key)
        } else {
            None
        }
    }

    pub fn as_secp256r1_pub_key(&self) -> &Secp256r1PublicKey {
        self.as_secp256r1_pub_key_opt()
            .expect("not an secp256r1 public key")
    }

    pub fn into_secp256r1_opt(self) -> Option<(Secp256r1Signature, Secp256r1PublicKey)> {
        if let Self::Secp256r1 {
            signature,
            public_key,
            ..
        } = self
        {
            Some((signature, public_key))
        } else {
            None
        }
    }

    pub fn into_secp256r1(self) -> (Secp256r1Signature, Secp256r1PublicKey) {
        self.into_secp256r1_opt()
            .expect("not an secp256r1 signature")
    }

    /// Return the flag for this signature scheme
    pub fn scheme(&self) -> SignatureScheme {
        match self {
            SimpleSignature::Ed25519 { .. } => SignatureScheme::Ed25519,
            SimpleSignature::Secp256k1 { .. } => SignatureScheme::Secp256k1,
            SimpleSignature::Secp256r1 { .. } => SignatureScheme::Secp256r1,
        }
    }
}

/// Flag use to disambiguate the signature schemes supported by IOTA.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// signature-scheme = ed25519-flag / secp256k1-flag / secp256r1-flag /
///                    multisig-flag / bls-flag / zklogin-auth-flag-deprecated / passkey-auth-flag /
///                    move-auth-flag
/// ed25519-flag                    = %d00
/// secp256k1-flag                  = %d01
/// secp256r1-flag                  = %d02
/// multisig-flag                   = %d03
/// bls-flag                        = %d04
/// zklogin-auth-flag-deprecated    = %d05
/// passkey-auth-flag               = %d06
/// move-auth-flag                  = %d07
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, strum::Display)]
#[strum(serialize_all = "lowercase")]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[repr(u8)]
#[non_exhaustive]
pub enum SignatureScheme {
    Ed25519 = 0x00,
    Secp256k1 = 0x01,
    Secp256r1 = 0x02,
    Multisig = 0x03,
    Bls12381 = 0x04, // This is currently not supported for user addresses
    ZkLoginAuthenticatorDeprecated = 0x05,
    PasskeyAuthenticator = 0x06,
    MoveAuthenticator = 0x07,
}

impl SignatureScheme {
    crate::def_is!(
        Ed25519,
        Secp256k1,
        Secp256r1,
        Multisig,
        Bls12381,
        PasskeyAuthenticator,
        MoveAuthenticator,
    );

    /// Try constructing from a byte flag
    pub fn from_byte(flag: u8) -> Result<Self, InvalidSignatureScheme> {
        match flag {
            0x00 => Ok(Self::Ed25519),
            0x01 => Ok(Self::Secp256k1),
            0x02 => Ok(Self::Secp256r1),
            0x03 => Ok(Self::Multisig),
            0x04 => Ok(Self::Bls12381),
            0x05 => Ok(Self::ZkLoginAuthenticatorDeprecated),
            0x06 => Ok(Self::PasskeyAuthenticator),
            0x07 => Ok(Self::MoveAuthenticator),
            invalid => Err(InvalidSignatureScheme(invalid)),
        }
    }

    /// Convert to a byte flag
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl super::PasskeyPublicKey {
    /// Return the flag for this signature scheme
    pub fn scheme(&self) -> SignatureScheme {
        SignatureScheme::PasskeyAuthenticator
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, thiserror::Error)]
pub struct InvalidSignatureScheme(u8);

impl std::fmt::Display for InvalidSignatureScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid signature scheme: {:02x}", self.0)
    }
}

/// A signature from a user
///
/// A `UserSignature` is most commonly used to authorize the execution and
/// inclusion of a transaction to the blockchain.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// user-signature-bcs = bytes ; where the contents of the bytes are defined by <user-signature>
/// user-signature = simple-signature / multisig / multisig-legacy / zklogin / passkey / move-authenticator
/// ```
///
/// Note: Due to historical reasons, signatures are serialized slightly
/// different from the majority of the types in IOTA. In particular if a
/// signature is ever embedded in another structure it generally is serialized
/// as `bytes` meaning it has a length prefix that defines the length of
/// the completely serialized signature.
#[derive(Clone, Debug, derive_more::From, Eq, PartialEq)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(
    feature = "bcs-schema",
    derive(iota_bcs_schema::BcsSchema),
    bcs_schema(definition = "bytes")
)]
#[non_exhaustive]
pub enum UserSignature {
    Simple(SimpleSignature),
    Multisig(MultisigAggregatedSignature),
    ZkLoginAuthenticatorDeprecated,
    PasskeyAuthenticator(PasskeyAuthenticator),
    MoveAuthenticator(MoveAuthenticator),
}

impl UserSignature {
    crate::def_is_as_into_opt!(
        Simple(SimpleSignature),
        Multisig(MultisigAggregatedSignature),
        PasskeyAuthenticator(PasskeyAuthenticator),
        MoveAuthenticator(MoveAuthenticator)
    );

    /// Return the flag for this signature scheme
    pub fn scheme(&self) -> SignatureScheme {
        match self {
            UserSignature::Simple(simple) => simple.scheme(),
            UserSignature::Multisig(_) => SignatureScheme::Multisig,
            UserSignature::ZkLoginAuthenticatorDeprecated => {
                SignatureScheme::ZkLoginAuthenticatorDeprecated
            }
            UserSignature::PasskeyAuthenticator(_) => SignatureScheme::PasskeyAuthenticator,
            UserSignature::MoveAuthenticator(_) => SignatureScheme::MoveAuthenticator,
        }
    }

    /// Return the public key for this signature, if the scheme supports it.
    pub fn to_public_key(&self) -> Result<PublicKey, InvalidSignatureScheme> {
        match self {
            UserSignature::Simple(simple) => match simple {
                SimpleSignature::Ed25519 { public_key, .. } => Ok(PublicKey::Ed25519(*public_key)),
                SimpleSignature::Secp256k1 { public_key, .. } => {
                    Ok(PublicKey::Secp256k1(*public_key))
                }
                SimpleSignature::Secp256r1 { public_key, .. } => {
                    Ok(PublicKey::Secp256r1(*public_key))
                }
            },
            UserSignature::Multisig(_) => {
                Err(InvalidSignatureScheme(SignatureScheme::Multisig.to_u8()))
            }
            UserSignature::ZkLoginAuthenticatorDeprecated => Err(InvalidSignatureScheme(
                SignatureScheme::ZkLoginAuthenticatorDeprecated.to_u8(),
            )),
            UserSignature::PasskeyAuthenticator(passkey_authenticator) => {
                Ok(PublicKey::Passkey(passkey_authenticator.public_key()))
            }
            UserSignature::MoveAuthenticator(_) => Err(InvalidSignatureScheme(
                SignatureScheme::MoveAuthenticator.to_u8(),
            )),
        }
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization {
    use std::str::FromStr;

    use super::*;
    use crate::crypto::SignatureFromBytesError;

    impl SimpleSignature {
        pub fn to_bytes(&self) -> Vec<u8> {
            let mut buf = Vec::new();
            match self {
                SimpleSignature::Ed25519 {
                    signature,
                    public_key,
                } => {
                    buf.push(SignatureScheme::Ed25519 as u8);
                    buf.extend_from_slice(signature.as_ref());
                    buf.extend_from_slice(public_key.as_ref());
                }
                SimpleSignature::Secp256k1 {
                    signature,
                    public_key,
                } => {
                    buf.push(SignatureScheme::Secp256k1 as u8);
                    buf.extend_from_slice(signature.as_ref());
                    buf.extend_from_slice(public_key.as_ref());
                }
                SimpleSignature::Secp256r1 {
                    signature,
                    public_key,
                } => {
                    buf.push(SignatureScheme::Secp256r1 as u8);
                    buf.extend_from_slice(signature.as_ref());
                    buf.extend_from_slice(public_key.as_ref());
                }
            }

            buf
        }

        pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, SignatureFromBytesError> {
            let bytes = bytes.as_ref();
            let flag =
                SignatureScheme::from_byte(*bytes.first().ok_or_else(|| {
                    SignatureFromBytesError::new("missing signature scheme flag")
                })?)
                .map_err(SignatureFromBytesError::new)?;
            match flag {
                SignatureScheme::Ed25519 => {
                    let expected_length = 1 + Ed25519Signature::LENGTH + Ed25519PublicKey::LENGTH;

                    if bytes.len() != expected_length {
                        return Err(SignatureFromBytesError::new("invalid ed25519 signature"));
                    }

                    let mut signature = [0; Ed25519Signature::LENGTH];
                    signature.copy_from_slice(&bytes[1..(1 + Ed25519Signature::LENGTH)]);

                    let mut public_key = [0; Ed25519PublicKey::LENGTH];
                    public_key.copy_from_slice(&bytes[(1 + Ed25519Signature::LENGTH)..]);

                    Ok(SimpleSignature::Ed25519 {
                        signature: Ed25519Signature::new(signature),
                        public_key: Ed25519PublicKey::new(public_key),
                    })
                }
                SignatureScheme::Secp256k1 => {
                    let expected_length =
                        1 + Secp256k1Signature::LENGTH + Secp256k1PublicKey::LENGTH;

                    if bytes.len() != expected_length {
                        return Err(SignatureFromBytesError::new("invalid secp25k1 signature"));
                    }

                    let mut signature = [0; Secp256k1Signature::LENGTH];
                    signature.copy_from_slice(&bytes[1..(1 + Secp256k1Signature::LENGTH)]);

                    let mut public_key = [0; Secp256k1PublicKey::LENGTH];
                    public_key.copy_from_slice(&bytes[(1 + Secp256k1Signature::LENGTH)..]);

                    Ok(SimpleSignature::Secp256k1 {
                        signature: Secp256k1Signature::new(signature),
                        public_key: Secp256k1PublicKey::new(public_key),
                    })
                }
                SignatureScheme::Secp256r1 => {
                    let expected_length =
                        1 + Secp256r1Signature::LENGTH + Secp256r1PublicKey::LENGTH;

                    if bytes.len() != expected_length {
                        return Err(SignatureFromBytesError::new("invalid secp25r1 signature"));
                    }

                    let mut signature = [0; Secp256r1Signature::LENGTH];
                    signature.copy_from_slice(&bytes[1..(1 + Secp256r1Signature::LENGTH)]);

                    let mut public_key = [0; Secp256r1PublicKey::LENGTH];
                    public_key.copy_from_slice(&bytes[(1 + Secp256r1Signature::LENGTH)..]);

                    Ok(SimpleSignature::Secp256r1 {
                        signature: Secp256r1Signature::new(signature),
                        public_key: Secp256r1PublicKey::new(public_key),
                    })
                }
                SignatureScheme::Multisig
                | SignatureScheme::Bls12381
                | SignatureScheme::ZkLoginAuthenticatorDeprecated
                | SignatureScheme::PasskeyAuthenticator
                | SignatureScheme::MoveAuthenticator => {
                    Err(SignatureFromBytesError::new("invalid signature scheme"))
                }
            }
        }
    }

    impl serde::Serialize for SimpleSignature {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            #[derive(serde::Serialize)]
            #[serde(tag = "scheme")]
            #[serde(rename_all = "lowercase")]
            enum Sig<'a> {
                Ed25519 {
                    signature: &'a Ed25519Signature,
                    public_key: &'a Ed25519PublicKey,
                },
                Secp256k1 {
                    signature: &'a Secp256k1Signature,
                    public_key: &'a Secp256k1PublicKey,
                },
                Secp256r1 {
                    signature: &'a Secp256r1Signature,
                    public_key: &'a Secp256r1PublicKey,
                },
            }

            if serializer.is_human_readable() {
                let sig = match self {
                    SimpleSignature::Ed25519 {
                        signature,
                        public_key,
                    } => Sig::Ed25519 {
                        signature,
                        public_key,
                    },
                    SimpleSignature::Secp256k1 {
                        signature,
                        public_key,
                    } => Sig::Secp256k1 {
                        signature,
                        public_key,
                    },
                    SimpleSignature::Secp256r1 {
                        signature,
                        public_key,
                    } => Sig::Secp256r1 {
                        signature,
                        public_key,
                    },
                };

                sig.serialize(serializer)
            } else {
                match self {
                    SimpleSignature::Ed25519 {
                        signature,
                        public_key,
                    } => {
                        let mut buf = [0; 1 + Ed25519Signature::LENGTH + Ed25519PublicKey::LENGTH];
                        buf[0] = SignatureScheme::Ed25519 as u8;
                        buf[1..(1 + Ed25519Signature::LENGTH)].copy_from_slice(signature.as_ref());
                        buf[(1 + Ed25519Signature::LENGTH)..].copy_from_slice(public_key.as_ref());

                        serializer.serialize_bytes(&buf)
                    }
                    SimpleSignature::Secp256k1 {
                        signature,
                        public_key,
                    } => {
                        let mut buf =
                            [0; 1 + Secp256k1Signature::LENGTH + Secp256k1PublicKey::LENGTH];
                        buf[0] = SignatureScheme::Secp256k1 as u8;
                        buf[1..(1 + Secp256k1Signature::LENGTH)]
                            .copy_from_slice(signature.as_ref());
                        buf[(1 + Secp256k1Signature::LENGTH)..]
                            .copy_from_slice(public_key.as_ref());

                        serializer.serialize_bytes(&buf)
                    }
                    SimpleSignature::Secp256r1 {
                        signature,
                        public_key,
                    } => {
                        let mut buf =
                            [0; 1 + Secp256r1Signature::LENGTH + Secp256r1PublicKey::LENGTH];
                        buf[0] = SignatureScheme::Secp256r1 as u8;
                        buf[1..(1 + Secp256r1Signature::LENGTH)]
                            .copy_from_slice(signature.as_ref());
                        buf[(1 + Secp256r1Signature::LENGTH)..]
                            .copy_from_slice(public_key.as_ref());

                        serializer.serialize_bytes(&buf)
                    }
                }
            }
        }
    }

    impl<'de> serde::Deserialize<'de> for SimpleSignature {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            #[derive(serde::Deserialize)]
            #[serde(tag = "scheme")]
            #[serde(rename_all = "lowercase")]
            enum Sig {
                Ed25519 {
                    signature: Ed25519Signature,
                    public_key: Ed25519PublicKey,
                },
                Secp256k1 {
                    signature: Secp256k1Signature,
                    public_key: Secp256k1PublicKey,
                },
                Secp256r1 {
                    signature: Secp256r1Signature,
                    public_key: Secp256r1PublicKey,
                },
            }

            if deserializer.is_human_readable() {
                let sig = Sig::deserialize(deserializer)?;
                Ok(match sig {
                    Sig::Ed25519 {
                        signature,
                        public_key,
                    } => SimpleSignature::Ed25519 {
                        signature,
                        public_key,
                    },
                    Sig::Secp256k1 {
                        signature,
                        public_key,
                    } => SimpleSignature::Secp256k1 {
                        signature,
                        public_key,
                    },
                    Sig::Secp256r1 {
                        signature,
                        public_key,
                    } => SimpleSignature::Secp256r1 {
                        signature,
                        public_key,
                    },
                })
            } else {
                let bytes: std::borrow::Cow<'de, [u8]> =
                    std::borrow::Cow::deserialize(deserializer)?;
                Self::from_bytes(bytes).map_err(serde::de::Error::custom)
            }
        }
    }

    impl UserSignature {
        pub fn to_bytes(&self) -> Vec<u8> {
            match self {
                UserSignature::Simple(s) => s.to_bytes(),
                UserSignature::Multisig(m) => m.to_bytes(),
                // Scheme flag only: the payload was dropped when zklogin was removed, but the
                // flag is retained to avoid having to panic or make the whole function fallible.
                UserSignature::ZkLoginAuthenticatorDeprecated => {
                    vec![SignatureScheme::ZkLoginAuthenticatorDeprecated as u8]
                }
                UserSignature::PasskeyAuthenticator(p) => p.to_bytes(),
                UserSignature::MoveAuthenticator(m) => m.to_bytes(),
            }
        }

        pub fn to_base64(&self) -> String {
            use base64ct::Encoding;

            base64ct::Base64::encode_string(&self.to_bytes())
        }

        pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, SignatureFromBytesError> {
            let bytes = bytes.as_ref();

            let flag =
                SignatureScheme::from_byte(*bytes.first().ok_or_else(|| {
                    SignatureFromBytesError::new("missing signature scheme flag")
                })?)
                .map_err(SignatureFromBytesError::new)?;
            match flag {
                SignatureScheme::Ed25519
                | SignatureScheme::Secp256k1
                | SignatureScheme::Secp256r1 => {
                    let simple = SimpleSignature::from_bytes(bytes)?;
                    Ok(Self::Simple(simple))
                }
                SignatureScheme::Multisig => {
                    let multisig = MultisigAggregatedSignature::from_bytes(bytes)?;
                    Ok(Self::Multisig(multisig))
                }
                SignatureScheme::Bls12381 => Err(SignatureFromBytesError::new(
                    "bls not supported for user signatures",
                )),
                SignatureScheme::ZkLoginAuthenticatorDeprecated => {
                    Ok(Self::ZkLoginAuthenticatorDeprecated)
                }
                SignatureScheme::PasskeyAuthenticator => {
                    let passkey = PasskeyAuthenticator::from_bytes(bytes)?;
                    Ok(Self::PasskeyAuthenticator(passkey))
                }
                SignatureScheme::MoveAuthenticator => {
                    let move_auth = MoveAuthenticator::from_bytes(bytes)?;
                    Ok(Self::MoveAuthenticator(move_auth))
                }
            }
        }

        pub fn from_base64(s: &str) -> Result<Self, bcs::Error> {
            use base64ct::Encoding;
            use serde::de::Error;

            let bytes = base64ct::Base64::decode_vec(s).map_err(bcs::Error::custom)?;
            Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
        }
    }

    #[derive(serde::Serialize)]
    #[serde(tag = "scheme", rename_all = "lowercase")]
    #[serde(rename = "UserSignature")]
    enum ReadableUserSignatureRef<'a> {
        Ed25519 {
            signature: &'a Ed25519Signature,
            public_key: &'a Ed25519PublicKey,
        },
        Secp256k1 {
            signature: &'a Secp256k1Signature,
            public_key: &'a Secp256k1PublicKey,
        },
        Secp256r1 {
            signature: &'a Secp256r1Signature,
            public_key: &'a Secp256r1PublicKey,
        },
        Multisig(&'a MultisigAggregatedSignature),
        ZkLoginDeprecated,
        Passkey(&'a PasskeyAuthenticator),
        Move(&'a MoveAuthenticator),
    }

    #[derive(serde::Deserialize)]
    #[serde(tag = "scheme", rename_all = "lowercase")]
    #[serde(rename = "UserSignature")]
    enum ReadableUserSignature {
        Ed25519 {
            signature: Ed25519Signature,
            public_key: Ed25519PublicKey,
        },
        Secp256k1 {
            signature: Secp256k1Signature,
            public_key: Secp256k1PublicKey,
        },
        Secp256r1 {
            signature: Secp256r1Signature,
            public_key: Secp256r1PublicKey,
        },
        Multisig(MultisigAggregatedSignature),
        ZkLoginDeprecated,
        Passkey(PasskeyAuthenticator),
        Move(MoveAuthenticator),
    }

    impl serde::Serialize for UserSignature {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            if serializer.is_human_readable() {
                let readable = match self {
                    UserSignature::Simple(SimpleSignature::Ed25519 {
                        signature,
                        public_key,
                    }) => ReadableUserSignatureRef::Ed25519 {
                        signature,
                        public_key,
                    },
                    UserSignature::Simple(SimpleSignature::Secp256k1 {
                        signature,
                        public_key,
                    }) => ReadableUserSignatureRef::Secp256k1 {
                        signature,
                        public_key,
                    },
                    UserSignature::Simple(SimpleSignature::Secp256r1 {
                        signature,
                        public_key,
                    }) => ReadableUserSignatureRef::Secp256r1 {
                        signature,
                        public_key,
                    },
                    UserSignature::Multisig(multisig) => {
                        ReadableUserSignatureRef::Multisig(multisig)
                    }
                    UserSignature::ZkLoginAuthenticatorDeprecated => {
                        ReadableUserSignatureRef::ZkLoginDeprecated
                    }
                    UserSignature::PasskeyAuthenticator(passkey) => {
                        ReadableUserSignatureRef::Passkey(passkey)
                    }
                    UserSignature::MoveAuthenticator(move_auth) => {
                        ReadableUserSignatureRef::Move(move_auth)
                    }
                };
                readable.serialize(serializer)
            } else {
                match self {
                    UserSignature::Simple(simple) => simple.serialize(serializer),
                    UserSignature::Multisig(multisig) => multisig.serialize(serializer),
                    UserSignature::ZkLoginAuthenticatorDeprecated => serializer
                        .serialize_bytes(&[SignatureScheme::ZkLoginAuthenticatorDeprecated as u8]),
                    UserSignature::PasskeyAuthenticator(passkey) => passkey.serialize(serializer),
                    UserSignature::MoveAuthenticator(move_auth) => move_auth.serialize(serializer),
                }
            }
        }
    }

    impl<'de> serde::Deserialize<'de> for UserSignature {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let readable = ReadableUserSignature::deserialize(deserializer)?;
                Ok(match readable {
                    ReadableUserSignature::Ed25519 {
                        signature,
                        public_key,
                    } => Self::Simple(SimpleSignature::Ed25519 {
                        signature,
                        public_key,
                    }),
                    ReadableUserSignature::Secp256k1 {
                        signature,
                        public_key,
                    } => Self::Simple(SimpleSignature::Secp256k1 {
                        signature,
                        public_key,
                    }),
                    ReadableUserSignature::Secp256r1 {
                        signature,
                        public_key,
                    } => Self::Simple(SimpleSignature::Secp256r1 {
                        signature,
                        public_key,
                    }),
                    ReadableUserSignature::Multisig(multisig) => Self::Multisig(multisig),
                    ReadableUserSignature::ZkLoginDeprecated => {
                        Self::ZkLoginAuthenticatorDeprecated
                    }
                    ReadableUserSignature::Passkey(passkey) => Self::PasskeyAuthenticator(passkey),
                    ReadableUserSignature::Move(move_auth) => Self::MoveAuthenticator(move_auth),
                })
            } else {
                use serde_with::DeserializeAs;

                let bytes: std::borrow::Cow<'de, [u8]> =
                    serde_with::Bytes::deserialize_as(deserializer)?;
                Self::from_bytes(bytes).map_err(serde::de::Error::custom)
            }
        }
    }

    impl FromStr for UserSignature {
        type Err = bcs::Error;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Self::from_base64(s)
        }
    }

    #[cfg(test)]
    mod tests {
        use base64ct::{Base64, Encoding};
        #[cfg(feature = "proptest")]
        use test_strategy::proptest;
        #[cfg(target_arch = "wasm32")]
        use wasm_bindgen_test::wasm_bindgen_test as test;

        use super::*;

        #[proptest]
        #[cfg(feature = "proptest")]
        fn roundtrip_signature_scheme(scheme: SignatureScheme) {
            assert_eq!(Ok(scheme), SignatureScheme::from_byte(scheme.to_u8()));
        }

        #[test]
        fn simple_fixtures() {
            const FIXTURES: &[(SignatureScheme, &str)] = &[
                (
                    SignatureScheme::Ed25519,
                    "YQDaeO4w2ULMy5eqHBzP0oalr1YhDX/9uJS9MntKnW3d55q4aqZYYnoEloaBmXKc6FoD5bTwONdwS9CwdMQGhIcPDX2rNYyNrapO+gBJp1sHQ2VVsQo2ghm7aA9wVxNJ13U=",
                ),
                (
                    SignatureScheme::Secp256k1,
                    "YgErcT6WUSQXGD1DaIwls5rWq648akDMlvL41ugUUhyIPWnqURl+daQLG+ILNemARKHYVNOikKJJ8jqu+HzlRa5rAg4XzVk55GsZZkGWjNdZkQuiV34n+nP944dtub7FvOsr",
                ),
                (
                    SignatureScheme::Secp256r1,
                    "YgLp1p4K9dSQTt2AeR05yK1MkXmtLm6Sieb9yfkpW1gOBiqnO9ZKZiWUrLJQav2Mxw64zM37g3IVdsB/To6qfl8IA0f7ryPwOKvEwwiicRF6Kkz/rt28X/gcdRe8bHSn7bQw",
                ),
            ];

            for (scheme, fixture) in FIXTURES {
                let bcs = Base64::decode_vec(fixture).unwrap();

                let sig: UserSignature = bcs::from_bytes(&bcs).unwrap();
                assert_eq!(*scheme, sig.scheme());
                let bytes = bcs::to_bytes(&sig).unwrap();
                assert_eq!(bcs, bytes);

                let json = serde_json::to_string_pretty(&sig).unwrap();
                println!("{json}");
                assert_eq!(sig, serde_json::from_str(&json).unwrap());
            }
        }

        #[test]
        fn multisig_fixtures() {
            const FIXTURE1: &str = "sgIDAwCTLgVngjC4yeuvpAGKVkgcvIKVFUJnL1r6oFZScQVE5DNIz6kfxAGDRcVUczE9CUb7/sN/EuFJ8ot86Sdb8pAFASoQ91stRHXdW5dLy0BQ6v+7XWptawy2ItMyPk508p+PHdtZcm2aKl3lZGIvXe6MPY73E+1Hakv/xJbTYsw5SPMC5dx3gBwxds2GV12c7VUSqkyXamliSF1W/QBMufqrlmdIOZ1ox9gbsvIPtXYahfvKm8ozA7rsZWwRv8atsnyfYgcAAwANfas1jI2tqk76AEmnWwdDZVWxCjaCGbtoD3BXE0nXdQEBAg4XzVk55GsZZkGWjNdZkQuiV34n+nP944dtub7FvOsrAQIDR/uvI/A4q8TDCKJxEXoqTP+u3bxf+Bx1F7xsdKfttDABAgA=";

            const FIXTURE2: &str = "8QEDAgBMW4Oq7XMjO5c6HLgTBJrWDZsCEcZF2EPOf68fdf1aY3e3pvA3cmk0tjMmXFB9+A6J2NohCpTFb/CsXEBjtCcMAfraaMMOMzG815145jlrY44Rbp0d1JQJOJ3hjgEe2xVBFP3QR94IVZk6ssyYxsecpBA+re5eqVRacvZGSobNPkMDAAMADX2rNYyNrapO+gBJp1sHQ2VVsQo2ghm7aA9wVxNJ13UBAQIOF81ZOeRrGWZBlozXWZELold+J/pz/eOHbbm+xbzrKwECA0f7ryPwOKvEwwiicRF6Kkz/rt28X/gcdRe8bHSn7bQwAQIA";

            for fixture in [FIXTURE1, FIXTURE2] {
                let bcs = Base64::decode_vec(fixture).unwrap();

                let sig: UserSignature = bcs::from_bytes(&bcs).unwrap();
                assert_eq!(SignatureScheme::Multisig, sig.scheme());
                let bytes = bcs::to_bytes(&sig).unwrap();
                assert_eq!(bcs, bytes);

                let json = serde_json::to_string_pretty(&sig).unwrap();
                println!("{json}");
                assert_eq!(sig, serde_json::from_str(&json).unwrap());
            }
        }

        #[test]
        fn passkey_fixtures() {
            const FIXTURES: &[&str] = &[
                "lgIGJUmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjHQAAAACKAXsidHlwZSI6IndlYmF1dGhuLmdldCIsImNoYWxsZW5nZSI6IkFBQUF0X21qSUIxdmJWcFlNNldWNllfb2l4Nko4YU5fOXNiOFNLRmJ1a0JmaVF3Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo1MTczIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfWICmOyQv1fJ+inKD0C/sxKtxyFKl9aoBign6p9Ih3iA2ahDVg2CPZqUOlEhur2S2GbIZjbn6TbgWtbXXg8SjLkL7wM9Fw4JO0AKLdnLC1nhQguHBX5K6Hv2ta1sqoOqEFDDEw==",
            ];

            for fixture in FIXTURES {
                let bcs = Base64::decode_vec(fixture).unwrap();

                let sig: UserSignature = bcs::from_bytes(&bcs).unwrap();
                assert_eq!(SignatureScheme::PasskeyAuthenticator, sig.scheme());
                let bytes = bcs::to_bytes(&sig).unwrap();
                assert_eq!(bcs, bytes);

                let json = serde_json::to_string_pretty(&sig).unwrap();
                println!("{json}");
                assert_eq!(sig, serde_json::from_str(&json).unwrap());
            }
        }
    }
}
