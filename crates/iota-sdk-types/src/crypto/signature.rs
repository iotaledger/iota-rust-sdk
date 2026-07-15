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

    /// The raw signature bytes, without the scheme flag or the public key.
    pub fn signature_bytes(&self) -> &[u8] {
        match self {
            SimpleSignature::Ed25519 { signature, .. } => signature.as_ref(),
            SimpleSignature::Secp256k1 { signature, .. } => signature.as_ref(),
            SimpleSignature::Secp256r1 { signature, .. } => signature.as_ref(),
        }
    }

    /// The public key embedded in this signature.
    ///
    /// The raw public-key bytes are available via [`AsRef`] on the returned
    /// [`PublicKey`].
    pub fn to_public_key(&self) -> PublicKey {
        match self {
            SimpleSignature::Ed25519 { public_key, .. } => PublicKey::Ed25519(*public_key),
            SimpleSignature::Secp256k1 { public_key, .. } => PublicKey::Secp256k1(*public_key),
            SimpleSignature::Secp256r1 { public_key, .. } => PublicKey::Secp256r1(*public_key),
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
///                    multisig-flag / bls-flag / passkey-auth-flag /
///                    move-auth-flag
/// ed25519-flag                    = %d00
/// secp256k1-flag                  = %d01
/// secp256r1-flag                  = %d02
/// multisig-flag                   = %d03
/// bls-flag                        = %d04
/// passkey-auth-flag               = %d06
/// move-auth-flag                  = %d07
/// ```
///
/// Flag `%d05` is reserved: it was formerly used for the now-removed zklogin
/// authenticator (which was never enabled on chain) and is intentionally
/// skipped.
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
/// user-signature = simple-signature / multisig / multisig-legacy / passkey / move-authenticator
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
impl std::hash::Hash for UserSignature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
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
                | SignatureScheme::PasskeyAuthenticator
                | SignatureScheme::MoveAuthenticator => {
                    Err(SignatureFromBytesError::new("invalid signature scheme"))
                }
            }
        }

        /// Base64-encode this signature as its `flag || sig || pubkey` bytes,
        /// the same layout as [`to_bytes`](Self::to_bytes).
        pub fn to_base64(&self) -> String {
            use base64ct::Encoding;

            base64ct::Base64::encode_string(&self.to_bytes())
        }

        /// Decode a signature from the Base64 form produced by
        /// [`to_base64`](Self::to_base64), i.e. base64 over the
        /// `flag || sig || pubkey` bytes.
        pub fn from_base64(s: &str) -> Result<Self, bcs::Error> {
            use base64ct::Encoding;
            use serde::de::Error;

            let bytes = base64ct::Base64::decode_vec(s).map_err(bcs::Error::custom)?;
            Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
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
                    UserSignature::PasskeyAuthenticator(passkey) => passkey.serialize(serializer),
                    // `MoveAuthenticator` derives `Serialize`, so delegating here would emit the
                    // bare enum instead of the length-prefixed `flag || payload` byte blob every
                    // other signature scheme uses (and that `from_bytes`/deserialize expect).
                    UserSignature::MoveAuthenticator(move_auth) => {
                        serializer.serialize_bytes(&move_auth.to_bytes())
                    }
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

        /// The `SignatureScheme` flag bytes are part of the on-chain wire
        /// format and must never change. They are pinned here against
        /// hardcoded values; a round-trip (`roundtrip_signature_scheme`)
        /// cannot catch a shifted value because it would move in lockstep.
        /// `0x05` is reserved for the removed zklogin authenticator (never
        /// enabled on chain) and must be rejected rather than mapped.
        #[test]
        fn signature_scheme_flag_values() {
            assert_eq!(SignatureScheme::Ed25519.to_u8(), 0x00);
            assert_eq!(SignatureScheme::Secp256k1.to_u8(), 0x01);
            assert_eq!(SignatureScheme::Secp256r1.to_u8(), 0x02);
            assert_eq!(SignatureScheme::Multisig.to_u8(), 0x03);
            assert_eq!(SignatureScheme::Bls12381.to_u8(), 0x04);
            assert_eq!(SignatureScheme::PasskeyAuthenticator.to_u8(), 0x06);
            assert_eq!(SignatureScheme::MoveAuthenticator.to_u8(), 0x07);

            assert_eq!(
                SignatureScheme::from_byte(0x00),
                Ok(SignatureScheme::Ed25519)
            );
            assert_eq!(
                SignatureScheme::from_byte(0x01),
                Ok(SignatureScheme::Secp256k1)
            );
            assert_eq!(
                SignatureScheme::from_byte(0x02),
                Ok(SignatureScheme::Secp256r1)
            );
            assert_eq!(
                SignatureScheme::from_byte(0x03),
                Ok(SignatureScheme::Multisig)
            );
            assert_eq!(
                SignatureScheme::from_byte(0x04),
                Ok(SignatureScheme::Bls12381)
            );
            assert_eq!(
                SignatureScheme::from_byte(0x06),
                Ok(SignatureScheme::PasskeyAuthenticator)
            );
            assert_eq!(
                SignatureScheme::from_byte(0x07),
                Ok(SignatureScheme::MoveAuthenticator)
            );

            assert!(
                SignatureScheme::from_byte(0x05).is_err(),
                "0x05 (deprecated zklogin) must be rejected"
            );
        }

        /// A bare `0x05` flag previously decoded to the (removed) zklogin
        /// variant; it must now fail to decode.
        #[test]
        fn user_signature_rejects_zklogin_flag() {
            assert!(UserSignature::from_bytes([0x05]).is_err());
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
        fn simple_signature_base64_roundtrip() {
            const FIXTURES: &[&str] = &[
                "YQDaeO4w2ULMy5eqHBzP0oalr1YhDX/9uJS9MntKnW3d55q4aqZYYnoEloaBmXKc6FoD5bTwONdwS9CwdMQGhIcPDX2rNYyNrapO+gBJp1sHQ2VVsQo2ghm7aA9wVxNJ13U=",
                "YgErcT6WUSQXGD1DaIwls5rWq648akDMlvL41ugUUhyIPWnqURl+daQLG+ILNemARKHYVNOikKJJ8jqu+HzlRa5rAg4XzVk55GsZZkGWjNdZkQuiV34n+nP944dtub7FvOsr",
                "YgLp1p4K9dSQTt2AeR05yK1MkXmtLm6Sieb9yfkpW1gOBiqnO9ZKZiWUrLJQav2Mxw64zM37g3IVdsB/To6qfl8IA0f7ryPwOKvEwwiicRF6Kkz/rt28X/gcdRe8bHSn7bQw",
            ];

            for fixture in FIXTURES {
                let bcs = Base64::decode_vec(fixture).unwrap();
                let UserSignature::Simple(simple) = bcs::from_bytes(&bcs).unwrap() else {
                    panic!("fixture is not a simple signature");
                };

                // Base64 is over the same `flag || sig || pubkey` bytes.
                assert_eq!(
                    simple.to_base64(),
                    Base64::encode_string(&simple.to_bytes())
                );
                // Round-trips through base64.
                assert_eq!(
                    simple,
                    SimpleSignature::from_base64(&simple.to_base64()).unwrap()
                );
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
                // Mainnet transaction 4Q3oszHu1odYYaEAnWjs4Bqr1vGknLyxk2wegNsVpF2F
                "sAIGJVIGKHem4dhOwiP7NS5lmWKsKzH/Ffw8mln4BnYuS8lRBQAAAs+kAXsidHlwZSI6IndlYmF1dGhuLmdldCIsImNoYWxsZW5nZSI6IjJlempUVXlxSmdVTzVDbTAwejNaVFBoMmJHRjBzSFhmZzZIam1ESU03SlEiLCJvcmlnaW4iOiJjaHJvbWUtZXh0ZW5zaW9uOi8vaWlkamttZGNlb2xnaGVwZWhhYWRkb2ptbmpua2tpamEiLCJjcm9zc09yaWdpbiI6ZmFsc2V9YgJjv47OyCFpQ3B7WydR418Vgr5pwCsaKCUKS7610qe110rI2KKZ/BBQObH7ttlbKidRsopicGpzVgzaH+GO1i4jA/+3nSjF1JbAfNbIuTAgHY58Xt5m0jkaPMfUIohYtwfz",
                // testnet transaction HPeFPYFLvJqtxrmbifi42zFQgoCRUDyzqksGP6j816sf
                "nQMGJSHORCNS/1Poy7GQoBF5FEqa+43LJNIjx92KSNEd8LaHHQAAAACRAnsidHlwZSI6IndlYmF1dGhuLmdldCIsImNoYWxsZW5nZSI6InY5QWsyRGFTTm9KSVktTHF6R0R1QTdYZm1vN3NyNTAzMkRWdUJnVTVNSk0iLCJvcmlnaW4iOiJjaHJvbWUtZXh0ZW5zaW9uOi8vbmxtbGxwZmxwZWxwYW5ucGlqaGhuYmhla3BicGVqY2giLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifWICYGCmTmyHT8D9ZLWqejm60Joc0Qmrc9xZIVVkCR2kQ1QnZ08GMESPpCJYZ7ssqX023wtD6ekpMguLJenJd+XI0wKaO4p1lN2QJGk50UDzk7/iqYS/MZPM3oH8ywHemq1shg==",
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

        #[test]
        fn move_authenticator_fixtures() {
            // BCS form of on-chain `MoveAuthenticator` user signatures: the
            // length-prefixed `flag || payload` byte blob, matching the raw
            // fixtures in `move_authenticator.rs`. The Move variant derives
            // `Serialize`, so this pins it to the `bytes` wire form shared by
            // every other scheme rather than the bare enum encoding.
            const FIXTURES: &[&str] = &[
                // testnet/ALZRemHMDS7L5hTvNbsqBo3m9ppHdss9fnYBrhg5Goj1 (aa_account::AaAccount)
                "cgcAAQBBQHXo3l3VcV9Td7kSzIjdCcFaY7+nhwYn0/FAK8OKW7Vpve1bLrpkfvITLYzNphI2xHv45H2k+el6SVdM+45CZQgAAQHN7ufjvWgbqrk+iJudkpDtJJMBIXO1q4OmR3b+n4krQEQrQiwAAAAAAA==",
                // devnet/DYTjjcdMLU3VNnisMC64WRrVkYKqPWWsL1EnTwoxAJm8 (hello_auth::HelloAccount)
                "NwcAAQAGBWhlbGxvAAEBThUX6MUxNFwWwKJjH2T7SnsUAw0EmSPuWkfa8UZC3okAFQAAAAAAAAA=",
            ];

            for fixture in FIXTURES {
                let bcs = Base64::decode_vec(fixture).unwrap();

                let sig: UserSignature = bcs::from_bytes(&bcs).unwrap();
                assert_eq!(SignatureScheme::MoveAuthenticator, sig.scheme());
                let bytes = bcs::to_bytes(&sig).unwrap();
                assert_eq!(bcs, bytes);

                let json = serde_json::to_string_pretty(&sig).unwrap();
                println!("{json}");
                assert_eq!(sig, serde_json::from_str(&json).unwrap());
            }
        }
    }
}
