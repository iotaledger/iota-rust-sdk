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
/// simple-signature = bytes ; where the contents of the bytes are defined by
///                          ; <simple-signature-body>
/// simple-signature-body = (ed25519-flag ed25519-signature ed25519-public-key) /
///                         (secp256k1-flag secp256k1-signature secp256k1-public-key) /
///                         (secp256r1-flag secp256r1-signature secp256r1-public-key)
/// ```
///
/// Note: Due to historical reasons, signatures are serialized slightly
/// different from the majority of the types in IOTA. In particular if a
/// signature is ever embedded in another structure it generally is serialized
/// as `bytes` meaning it has a length prefix that defines the length of
/// the completely serialized signature.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(
    feature = "bcs-schema",
    derive(iota_bcs_schema::BcsSchema),
    bcs_schema(definition = "bytes")
)]
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

    pub fn as_opt_ed25519_signature(&self) -> Option<&Ed25519Signature> {
        if let Self::Ed25519 { signature, .. } = self {
            Some(signature)
        } else {
            None
        }
    }

    pub fn as_ed25519_signature(&self) -> &Ed25519Signature {
        self.as_opt_ed25519_signature()
            .expect("not an ed25519 signature")
    }

    pub fn as_opt_ed25519_public_key(&self) -> Option<&Ed25519PublicKey> {
        if let Self::Ed25519 { public_key, .. } = self {
            Some(public_key)
        } else {
            None
        }
    }

    pub fn as_ed25519_public_key(&self) -> &Ed25519PublicKey {
        self.as_opt_ed25519_public_key()
            .expect("not an ed25519 public key")
    }

    pub fn into_opt_ed25519(self) -> Option<(Ed25519Signature, Ed25519PublicKey)> {
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
        self.into_opt_ed25519().expect("not an ed25519 signature")
    }

    pub fn as_opt_secp256k1_signature(&self) -> Option<&Secp256k1Signature> {
        if let Self::Secp256k1 { signature, .. } = self {
            Some(signature)
        } else {
            None
        }
    }

    pub fn as_secp256k1_signature(&self) -> &Secp256k1Signature {
        self.as_opt_secp256k1_signature()
            .expect("not an secp256k1 signature")
    }

    pub fn as_opt_secp256k1_public_key(&self) -> Option<&Secp256k1PublicKey> {
        if let Self::Secp256k1 { public_key, .. } = self {
            Some(public_key)
        } else {
            None
        }
    }

    pub fn as_secp256k1_public_key(&self) -> &Secp256k1PublicKey {
        self.as_opt_secp256k1_public_key()
            .expect("not an secp256k1 public key")
    }

    pub fn into_opt_secp256k1(self) -> Option<(Secp256k1Signature, Secp256k1PublicKey)> {
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
        self.into_opt_secp256k1()
            .expect("not an secp256k1 signature")
    }

    pub fn as_opt_secp256r1_signature(&self) -> Option<&Secp256r1Signature> {
        if let Self::Secp256r1 { signature, .. } = self {
            Some(signature)
        } else {
            None
        }
    }

    pub fn as_secp256r1_signature(&self) -> &Secp256r1Signature {
        self.as_opt_secp256r1_signature()
            .expect("not an secp256r1 signature")
    }

    pub fn as_opt_secp256r1_public_key(&self) -> Option<&Secp256r1PublicKey> {
        if let Self::Secp256r1 { public_key, .. } = self {
            Some(public_key)
        } else {
            None
        }
    }

    pub fn as_secp256r1_public_key(&self) -> &Secp256r1PublicKey {
        self.as_opt_secp256r1_public_key()
            .expect("not an secp256r1 public key")
    }

    pub fn into_opt_secp256r1(self) -> Option<(Secp256r1Signature, Secp256r1PublicKey)> {
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
        self.into_opt_secp256r1()
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

impl crate::TreeDisplay for SimpleSignature {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.enum_name("Simple Signature");
        let (scheme, public_key, signature): (_, &dyn std::fmt::Display, &dyn std::fmt::Display) =
            match self {
                SimpleSignature::Ed25519 {
                    signature,
                    public_key,
                } => ("Ed25519Signature", public_key, signature),
                SimpleSignature::Secp256k1 {
                    signature,
                    public_key,
                } => ("Secp256k1Signature", public_key, signature),
                SimpleSignature::Secp256r1 {
                    signature,
                    public_key,
                } => ("Secp256r1Signature", public_key, signature),
            };
        w.header(scheme)?;
        w.leaf("Public Key", public_key, false)?;
        w.leaf("Signature", signature, true)
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
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, strum::Display, strum::EnumString,
)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[repr(u8)]
#[non_exhaustive]
pub enum SignatureScheme {
    #[strum(to_string = "Ed25519", serialize = "ed25519")]
    Ed25519 = 0x00,
    #[strum(to_string = "Secp256k1", serialize = "secp256k1")]
    Secp256k1 = 0x01,
    #[strum(to_string = "Secp256r1", serialize = "secp256r1")]
    Secp256r1 = 0x02,
    #[strum(to_string = "Multisig", serialize = "multisig")]
    Multisig = 0x03,
    // This is currently not supported for user addresses
    #[strum(to_string = "Bls12381", serialize = "bls12381")]
    Bls12381 = 0x04,
    #[strum(to_string = "PasskeyAuthenticator", serialize = "passkeyauthenticator")]
    PasskeyAuthenticator = 0x06,
    #[strum(to_string = "MoveAuthenticator", serialize = "moveauthenticator")]
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
    pub fn from_byte(flag: u8) -> Result<Self, InvalidSignatureSchemeError> {
        match flag {
            0x00 => Ok(Self::Ed25519),
            0x01 => Ok(Self::Secp256k1),
            0x02 => Ok(Self::Secp256r1),
            0x03 => Ok(Self::Multisig),
            0x04 => Ok(Self::Bls12381),
            0x06 => Ok(Self::PasskeyAuthenticator),
            0x07 => Ok(Self::MoveAuthenticator),
            invalid => Err(InvalidSignatureSchemeError(invalid)),
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
#[error("invalid signature scheme: {0:02x}")]
pub struct InvalidSignatureSchemeError(u8);

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
/// user-signature = bytes ; where the contents of the bytes are defined by
///                        ; <user-signature-body>
/// user-signature-body = simple-signature-body / multisig / passkey / move-authenticator
/// ```
///
/// Note: Due to historical reasons, signatures are serialized slightly
/// different from the majority of the types in IOTA. In particular if a
/// signature is ever embedded in another structure it generally is serialized
/// as `bytes` meaning it has a length prefix that defines the length of
/// the completely serialized signature.
#[derive(Clone, Debug, derive_more::From, Eq, Hash, PartialEq)]
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

impl crate::TreeDisplay for UserSignature {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.enum_name("User Signature");
        match self {
            Self::Simple(v) => v.fmt_tree(w),
            Self::Multisig(v) => v.fmt_tree(w),
            Self::PasskeyAuthenticator(v) => v.fmt_tree(w),
            Self::MoveAuthenticator(v) => v.fmt_tree(w),
        }
    }
}

crate::impl_tree_display!(SimpleSignature, UserSignature);

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
    pub fn to_public_key(&self) -> Result<PublicKey, InvalidSignatureSchemeError> {
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
            UserSignature::Multisig(_) => Err(InvalidSignatureSchemeError(
                SignatureScheme::Multisig.to_u8(),
            )),
            UserSignature::PasskeyAuthenticator(passkey_authenticator) => {
                Ok(PublicKey::Passkey(passkey_authenticator.public_key()))
            }
            UserSignature::MoveAuthenticator(_) => Err(InvalidSignatureSchemeError(
                SignatureScheme::MoveAuthenticator.to_u8(),
            )),
        }
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization {
    use std::{borrow::Cow, str::FromStr};

    use serde_with::{Bytes, DeserializeAs};

    use super::*;
    use crate::crypto::SignatureFromBytesError;

    // -----------------------------------------------------------------------
    // SimpleSignature
    // -----------------------------------------------------------------------

    /// Flat wire shape for `SimpleSignature`.
    ///
    /// Variant order matches the scheme flags (0x00 Ed25519, 0x01 Secp256k1,
    /// 0x02 Secp256r1) so BCS emits the correct byte for each variant
    /// automatically. All fields are `Copy`, so the same owned enum serves
    /// both serialization (built by copying) and deserialization.
    #[derive(serde::Deserialize, serde::Serialize)]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub(crate) enum SimpleSignatureBody {
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

    impl From<&SimpleSignature> for SimpleSignatureBody {
        fn from(sig: &SimpleSignature) -> Self {
            match *sig {
                SimpleSignature::Ed25519 {
                    signature,
                    public_key,
                } => Self::Ed25519 {
                    signature,
                    public_key,
                },
                SimpleSignature::Secp256k1 {
                    signature,
                    public_key,
                } => Self::Secp256k1 {
                    signature,
                    public_key,
                },
                SimpleSignature::Secp256r1 {
                    signature,
                    public_key,
                } => Self::Secp256r1 {
                    signature,
                    public_key,
                },
            }
        }
    }

    impl From<SimpleSignatureBody> for SimpleSignature {
        fn from(body: SimpleSignatureBody) -> Self {
            match body {
                SimpleSignatureBody::Ed25519 {
                    signature,
                    public_key,
                } => Self::Ed25519 {
                    signature,
                    public_key,
                },
                SimpleSignatureBody::Secp256k1 {
                    signature,
                    public_key,
                } => Self::Secp256k1 {
                    signature,
                    public_key,
                },
                SimpleSignatureBody::Secp256r1 {
                    signature,
                    public_key,
                } => Self::Secp256r1 {
                    signature,
                    public_key,
                },
            }
        }
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(tag = "scheme", rename_all = "lowercase")]
    #[serde(rename = "SimpleSignature")]
    enum ReadableSimpleSignature {
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

    impl From<&SimpleSignature> for ReadableSimpleSignature {
        fn from(sig: &SimpleSignature) -> Self {
            match *sig {
                SimpleSignature::Ed25519 {
                    signature,
                    public_key,
                } => Self::Ed25519 {
                    signature,
                    public_key,
                },
                SimpleSignature::Secp256k1 {
                    signature,
                    public_key,
                } => Self::Secp256k1 {
                    signature,
                    public_key,
                },
                SimpleSignature::Secp256r1 {
                    signature,
                    public_key,
                } => Self::Secp256r1 {
                    signature,
                    public_key,
                },
            }
        }
    }

    impl From<ReadableSimpleSignature> for SimpleSignature {
        fn from(r: ReadableSimpleSignature) -> Self {
            match r {
                ReadableSimpleSignature::Ed25519 {
                    signature,
                    public_key,
                } => Self::Ed25519 {
                    signature,
                    public_key,
                },
                ReadableSimpleSignature::Secp256k1 {
                    signature,
                    public_key,
                } => Self::Secp256k1 {
                    signature,
                    public_key,
                },
                ReadableSimpleSignature::Secp256r1 {
                    signature,
                    public_key,
                } => Self::Secp256r1 {
                    signature,
                    public_key,
                },
            }
        }
    }

    impl SimpleSignature {
        /// Encode this signature as `<scheme-flag> <signature> <public-key>`.
        ///
        /// Note: this is the flat body shape — no outer length prefix.
        pub fn to_bytes(&self) -> Vec<u8> {
            bcs::to_bytes(&SimpleSignatureBody::from(self))
                .expect("BCS serialization of SimpleSignature cannot fail")
        }

        /// Decode a `SimpleSignature` from its flat-body byte encoding.
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
                | SignatureScheme::Secp256r1 => bcs::from_bytes::<SimpleSignatureBody>(bytes)
                    .map(Into::into)
                    .map_err(|_| {
                        SignatureFromBytesError::new(match flag {
                            SignatureScheme::Ed25519 => "invalid ed25519 signature",
                            SignatureScheme::Secp256k1 => "invalid secp25k1 signature",
                            _ => "invalid secp25r1 signature",
                        })
                    }),
                _ => Err(SignatureFromBytesError::new("invalid signature scheme")),
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
        pub fn from_base64(s: &str) -> Result<Self, SignatureFromBytesError> {
            use base64ct::Encoding;

            let bytes = base64ct::Base64::decode_vec(s).map_err(SignatureFromBytesError::new)?;
            Self::from_bytes(&bytes)
        }
    }

    impl serde::Serialize for SimpleSignature {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            if serializer.is_human_readable() {
                ReadableSimpleSignature::from(self).serialize(serializer)
            } else {
                serializer.serialize_bytes(&self.to_bytes())
            }
        }
    }

    impl<'de> serde::Deserialize<'de> for SimpleSignature {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                ReadableSimpleSignature::deserialize(deserializer).map(Into::into)
            } else {
                let bytes: Cow<'de, [u8]> = Bytes::deserialize_as(deserializer)?;
                Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
            }
        }
    }

    // -----------------------------------------------------------------------
    // UserSignature
    // -----------------------------------------------------------------------

    /// Decode-side wire shape for `UserSignature`: the flat
    /// `scheme-flag || payload` body inside the outer length prefix.
    ///
    /// Variant order matches the eight scheme flags so the BCS variant tag is
    /// the scheme byte. `Bls12381Reserved` and `ZkLoginDeprecated` hold the
    /// `0x04`/`0x05` slots (keeping `Passkey` at `0x06`); the `TryFrom`
    /// conversion rejects both because they are not valid user signature
    /// schemes, and they are `bcs_schema(skip)`ped from the generated grammar.
    ///
    /// The multisig and passkey variants hold the flat body pivots rather
    /// than the public types, whose own serde emits the historical
    /// `bytes`-wrapped `flag || body` form.
    #[derive(serde::Deserialize)]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub(crate) enum UserSignatureBody {
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
        Multisig(
            #[cfg_attr(
                feature = "bcs-schema",
                bcs_schema(as_type = "multisig-aggregated-signature")
            )]
            crate::crypto::multisig::serialization::Multisig,
        ),
        #[cfg_attr(feature = "bcs-schema", bcs_schema(skip))]
        Bls12381Reserved,
        #[cfg_attr(feature = "bcs-schema", bcs_schema(skip))]
        ZkLoginDeprecated,
        Passkey(
            #[cfg_attr(feature = "bcs-schema", bcs_schema(as_type = "passkey-authenticator"))]
            crate::crypto::passkey::serialization::Authenticator,
        ),
        Move(MoveAuthenticator),
    }

    impl TryFrom<UserSignatureBody> for UserSignature {
        type Error = SignatureFromBytesError;

        fn try_from(body: UserSignatureBody) -> Result<Self, Self::Error> {
            Ok(match body {
                UserSignatureBody::Ed25519 {
                    signature,
                    public_key,
                } => Self::Simple(SimpleSignature::Ed25519 {
                    signature,
                    public_key,
                }),
                UserSignatureBody::Secp256k1 {
                    signature,
                    public_key,
                } => Self::Simple(SimpleSignature::Secp256k1 {
                    signature,
                    public_key,
                }),
                UserSignatureBody::Secp256r1 {
                    signature,
                    public_key,
                } => Self::Simple(SimpleSignature::Secp256r1 {
                    signature,
                    public_key,
                }),
                UserSignatureBody::Multisig(m) => Self::Multisig(m.try_into()?),
                UserSignatureBody::Bls12381Reserved => {
                    return Err(SignatureFromBytesError::new(
                        "bls not supported for user signatures",
                    ));
                }
                UserSignatureBody::ZkLoginDeprecated => {
                    return Err(SignatureFromBytesError::new(
                        "zklogin is not supported for user signatures",
                    ));
                }
                UserSignatureBody::Passkey(p) => Self::PasskeyAuthenticator(p.try_into()?),
                UserSignatureBody::Move(m) => Self::MoveAuthenticator(m),
            })
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

    impl<'a> From<&'a UserSignature> for ReadableUserSignatureRef<'a> {
        fn from(sig: &'a UserSignature) -> Self {
            match sig {
                UserSignature::Simple(SimpleSignature::Ed25519 {
                    signature,
                    public_key,
                }) => Self::Ed25519 {
                    signature,
                    public_key,
                },
                UserSignature::Simple(SimpleSignature::Secp256k1 {
                    signature,
                    public_key,
                }) => Self::Secp256k1 {
                    signature,
                    public_key,
                },
                UserSignature::Simple(SimpleSignature::Secp256r1 {
                    signature,
                    public_key,
                }) => Self::Secp256r1 {
                    signature,
                    public_key,
                },
                UserSignature::Multisig(m) => Self::Multisig(m),
                UserSignature::PasskeyAuthenticator(p) => Self::Passkey(p),
                UserSignature::MoveAuthenticator(m) => Self::Move(m),
            }
        }
    }

    impl From<ReadableUserSignature> for UserSignature {
        fn from(r: ReadableUserSignature) -> Self {
            match r {
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
                ReadableUserSignature::Multisig(m) => Self::Multisig(m),
                ReadableUserSignature::Passkey(p) => Self::PasskeyAuthenticator(p),
                ReadableUserSignature::Move(m) => Self::MoveAuthenticator(m),
            }
        }
    }

    impl UserSignature {
        /// Encode this signature as `<scheme-flag> <payload>`.
        ///
        /// Note: this is the flat body shape — no outer length prefix.
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

        /// Decode a `UserSignature` from its flat-body byte encoding.
        pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, SignatureFromBytesError> {
            let bytes = bytes.as_ref();
            let flag =
                SignatureScheme::from_byte(*bytes.first().ok_or_else(|| {
                    SignatureFromBytesError::new("missing signature scheme flag")
                })?)
                .map_err(SignatureFromBytesError::new)?;
            let body = bcs::from_bytes::<UserSignatureBody>(bytes).map_err(|_| {
                SignatureFromBytesError::new(match flag {
                    SignatureScheme::Ed25519 => "invalid ed25519 signature",
                    SignatureScheme::Secp256k1 => "invalid secp25k1 signature",
                    SignatureScheme::Secp256r1 => "invalid secp25r1 signature",
                    SignatureScheme::Multisig => "invalid multisig",
                    SignatureScheme::Bls12381 => "bls not supported for user signatures",
                    SignatureScheme::PasskeyAuthenticator => "invalid passkey",
                    SignatureScheme::MoveAuthenticator => "invalid move authenticator",
                })
            })?;
            body.try_into()
        }

        pub fn from_base64(s: &str) -> Result<Self, SignatureFromBytesError> {
            use base64ct::Encoding;

            let bytes = base64ct::Base64::decode_vec(s).map_err(SignatureFromBytesError::new)?;
            Self::from_bytes(&bytes)
        }
    }

    impl serde::Serialize for UserSignature {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            if serializer.is_human_readable() {
                ReadableUserSignatureRef::from(self).serialize(serializer)
            } else {
                serializer.serialize_bytes(&self.to_bytes())
            }
        }
    }

    impl<'de> serde::Deserialize<'de> for UserSignature {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                ReadableUserSignature::deserialize(deserializer).map(Into::into)
            } else {
                let bytes: Cow<'de, [u8]> = Bytes::deserialize_as(deserializer)?;
                Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
            }
        }
    }

    impl FromStr for UserSignature {
        type Err = SignatureFromBytesError;

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

        /// `FromStr` must accept exactly the lowercase strings produced by
        /// `Display`.
        #[test]
        fn signature_scheme_string_roundtrip() {
            use std::str::FromStr as _;

            for scheme in [
                SignatureScheme::Ed25519,
                SignatureScheme::Secp256k1,
                SignatureScheme::Secp256r1,
                SignatureScheme::Multisig,
                SignatureScheme::Bls12381,
                SignatureScheme::PasskeyAuthenticator,
                SignatureScheme::MoveAuthenticator,
            ] {
                assert_eq!(
                    SignatureScheme::from_str(&scheme.to_string()),
                    Ok(scheme),
                    "{scheme} must parse back to itself"
                );
            }

            assert_eq!(SignatureScheme::from_str("ed25519").unwrap().to_u8(), 0x00);
            assert_eq!(SignatureScheme::from_str("Ed25519").unwrap().to_u8(), 0x00);
            assert!(SignatureScheme::from_str("zklogin").is_err());
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
