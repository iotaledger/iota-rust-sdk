use super::{
    Ed25519PublicKey, Ed25519Signature, Secp256k1PublicKey, Secp256k1Signature, Secp256r1PublicKey,
    Secp256r1Signature, SignatureScheme,
    zklogin::{ZkLoginAuthenticator, ZkLoginPublicIdentifier},
};

pub type WeightUnit = u8;
pub type ThresholdUnit = u16;
pub type BitmapUnit = u16;

// TODO validate sigs
// const MAX_BITMAP_VALUE: BitmapUnit = 0b1111111111;

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(test_strategy::Arbitrary))]
pub enum MultisigMemberPublicKey {
    Ed25519(Ed25519PublicKey),
    Secp256k1(Secp256k1PublicKey),
    Secp256r1(Secp256r1PublicKey),
    ZkLogin(ZkLoginPublicIdentifier),
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Serialize, serde_derive::Deserialize)
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(test, derive(test_strategy::Arbitrary))]
pub struct MultisigMember {
    public_key: MultisigMemberPublicKey,
    weight: WeightUnit,
}

impl MultisigMember {
    pub fn public_key(&self) -> &MultisigMemberPublicKey {
        &self.public_key
    }

    pub fn weight(&self) -> WeightUnit {
        self.weight
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Serialize, serde_derive::Deserialize)
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(test, derive(test_strategy::Arbitrary))]
pub struct MultisigCommittee {
    /// A list of committee members and their corresponding weight.
    #[cfg_attr(test, any(proptest::collection::size_range(0..=10).lift()))]
    members: Vec<MultisigMember>,
    /// If the total weight of the public keys corresponding to verified
    /// signatures is larger than threshold, the Multisig is verified.
    threshold: ThresholdUnit,
}

impl MultisigCommittee {
    pub fn members(&self) -> &[MultisigMember] {
        &self.members
    }

    pub fn threshold(&self) -> ThresholdUnit {
        self.threshold
    }

    pub fn scheme(&self) -> SignatureScheme {
        SignatureScheme::Multisig
    }
}

/// The struct that contains signatures and public keys necessary for
/// authenticating a Multisig.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(test, derive(test_strategy::Arbitrary))]
pub struct MultisigAggregatedSignature {
    /// The plain signature encoded with signature scheme.
    #[cfg_attr(test, any(proptest::collection::size_range(0..=10).lift()))]
    signatures: Vec<MultisigMemberSignature>,
    /// A bitmap that indicates the position of which public key the signature
    /// should be authenticated with.
    bitmap: BitmapUnit,
    /// The public key encoded with each public key with its signature scheme
    /// used along with the corresponding weight.
    committee: MultisigCommittee,
}

impl MultisigAggregatedSignature {
    pub fn signatures(&self) -> &[MultisigMemberSignature] {
        &self.signatures
    }

    pub fn bitmap(&self) -> BitmapUnit {
        self.bitmap
    }

    pub fn committee(&self) -> &MultisigCommittee {
        &self.committee
    }
}

impl PartialEq for MultisigAggregatedSignature {
    fn eq(&self, other: &Self) -> bool {
        self.bitmap == other.bitmap
            && self.signatures == other.signatures
            && self.committee == other.committee
    }
}

impl Eq for MultisigAggregatedSignature {}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(test_strategy::Arbitrary))]
#[allow(clippy::large_enum_variant)]
pub enum MultisigMemberSignature {
    Ed25519(Ed25519Signature),
    Secp256k1(Secp256k1Signature),
    Secp256r1(Secp256r1Signature),
    ZkLogin(ZkLoginAuthenticator),
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization {
    use std::borrow::Cow;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::{Bytes, DeserializeAs};

    use super::*;
    use crate::types::{Ed25519PublicKey, Secp256k1PublicKey, Secp256r1PublicKey, SignatureScheme};

    #[derive(serde_derive::Deserialize)]
    pub struct Multisig {
        signatures: Vec<MultisigMemberSignature>,
        bitmap: BitmapUnit,
        committee: MultisigCommittee,
    }

    #[derive(serde_derive::Serialize)]
    pub struct MultisigRef<'a> {
        signatures: &'a [MultisigMemberSignature],
        bitmap: BitmapUnit,
        committee: &'a MultisigCommittee,
    }

    #[derive(serde_derive::Deserialize)]
    struct ReadableMultisigAggregatedSignature {
        signatures: Vec<MultisigMemberSignature>,
        bitmap: BitmapUnit,
        committee: MultisigCommittee,
    }

    #[derive(serde_derive::Serialize)]
    struct ReadableMultisigAggregatedSignatureRef<'a> {
        signatures: &'a [MultisigMemberSignature],
        bitmap: BitmapUnit,
        committee: &'a MultisigCommittee,
    }

    impl Serialize for MultisigAggregatedSignature {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = ReadableMultisigAggregatedSignatureRef {
                    signatures: &self.signatures,
                    bitmap: self.bitmap,
                    committee: &self.committee,
                };
                readable.serialize(serializer)
            } else {
                let mut buf = Vec::new();
                buf.push(SignatureScheme::Multisig as u8);

                let multisig = MultisigRef {
                    signatures: &self.signatures,
                    bitmap: self.bitmap,
                    committee: &self.committee,
                };
                bcs::serialize_into(&mut buf, &multisig).expect("serialization cannot fail");
                serializer.serialize_bytes(&buf)
            }
        }
    }

    impl<'de> Deserialize<'de> for MultisigAggregatedSignature {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let readable = ReadableMultisigAggregatedSignature::deserialize(deserializer)?;
                Ok(Self {
                    signatures: readable.signatures,
                    bitmap: readable.bitmap,
                    committee: readable.committee,
                })
            } else {
                let bytes: Cow<'de, [u8]> = Bytes::deserialize_as(deserializer)?;
                Self::from_serialized_bytes(bytes)
            }
        }
    }

    impl MultisigAggregatedSignature {
        pub(crate) fn from_serialized_bytes<T: AsRef<[u8]>, E: serde::de::Error>(
            bytes: T,
        ) -> Result<Self, E> {
            let bytes = bytes.as_ref();
            let flag = SignatureScheme::from_byte(
                *bytes
                    .first()
                    .ok_or_else(|| serde::de::Error::custom("missing signature scheme flag"))?,
            )
            .map_err(serde::de::Error::custom)?;
            if flag != SignatureScheme::Multisig {
                return Err(serde::de::Error::custom("invalid multisig flag"));
            }
            let bcs_bytes = &bytes[1..];

            if let Ok(multisig) = bcs::from_bytes::<Multisig>(bcs_bytes) {
                Ok(Self {
                    signatures: multisig.signatures,
                    bitmap: multisig.bitmap,
                    committee: multisig.committee,
                })
            } else {
                Err(serde::de::Error::custom("invalid multisig"))
            }
        }
    }

    #[derive(serde_derive::Serialize, serde_derive::Deserialize)]
    enum MemberPublicKey {
        Ed25519(Ed25519PublicKey),
        Secp256k1(Secp256k1PublicKey),
        Secp256r1(Secp256r1PublicKey),
        ZkLogin(ZkLoginPublicIdentifier),
    }

    #[derive(serde_derive::Serialize, serde_derive::Deserialize)]
    #[serde(tag = "scheme", rename_all = "lowercase")]
    #[serde(rename = "MultisigMemberPublicKey")]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    enum ReadableMemberPublicKey {
        Ed25519 { public_key: Ed25519PublicKey },
        Secp256k1 { public_key: Secp256k1PublicKey },
        Secp256r1 { public_key: Secp256r1PublicKey },
        ZkLogin(ZkLoginPublicIdentifier),
    }

    #[cfg(feature = "schemars")]
    impl schemars::JsonSchema for MultisigMemberPublicKey {
        fn schema_name() -> String {
            ReadableMemberPublicKey::schema_name()
        }

        fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
            ReadableMemberPublicKey::json_schema(gen)
        }
    }

    impl Serialize for MultisigMemberPublicKey {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = match self {
                    MultisigMemberPublicKey::Ed25519(public_key) => {
                        ReadableMemberPublicKey::Ed25519 {
                            public_key: *public_key,
                        }
                    }
                    MultisigMemberPublicKey::Secp256k1(public_key) => {
                        ReadableMemberPublicKey::Secp256k1 {
                            public_key: *public_key,
                        }
                    }
                    MultisigMemberPublicKey::Secp256r1(public_key) => {
                        ReadableMemberPublicKey::Secp256r1 {
                            public_key: *public_key,
                        }
                    }
                    MultisigMemberPublicKey::ZkLogin(public_id) => {
                        ReadableMemberPublicKey::ZkLogin(public_id.clone())
                    }
                };
                readable.serialize(serializer)
            } else {
                let binary = match self {
                    MultisigMemberPublicKey::Ed25519(public_key) => {
                        MemberPublicKey::Ed25519(*public_key)
                    }
                    MultisigMemberPublicKey::Secp256k1(public_key) => {
                        MemberPublicKey::Secp256k1(*public_key)
                    }
                    MultisigMemberPublicKey::Secp256r1(public_key) => {
                        MemberPublicKey::Secp256r1(*public_key)
                    }
                    MultisigMemberPublicKey::ZkLogin(public_id) => {
                        MemberPublicKey::ZkLogin(public_id.clone())
                    }
                };
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for MultisigMemberPublicKey {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let readable = ReadableMemberPublicKey::deserialize(deserializer)?;
                Ok(match readable {
                    ReadableMemberPublicKey::Ed25519 { public_key } => Self::Ed25519(public_key),
                    ReadableMemberPublicKey::Secp256k1 { public_key } => {
                        Self::Secp256k1(public_key)
                    }
                    ReadableMemberPublicKey::Secp256r1 { public_key } => {
                        Self::Secp256r1(public_key)
                    }
                    ReadableMemberPublicKey::ZkLogin(public_id) => Self::ZkLogin(public_id),
                })
            } else {
                let binary = MemberPublicKey::deserialize(deserializer)?;
                Ok(match binary {
                    MemberPublicKey::Ed25519(public_key) => Self::Ed25519(public_key),
                    MemberPublicKey::Secp256k1(public_key) => Self::Secp256k1(public_key),
                    MemberPublicKey::Secp256r1(public_key) => Self::Secp256r1(public_key),
                    MemberPublicKey::ZkLogin(public_id) => Self::ZkLogin(public_id),
                })
            }
        }
    }

    #[derive(serde_derive::Serialize, serde_derive::Deserialize)]
    #[allow(clippy::large_enum_variant)]
    enum MemberSignature {
        Ed25519(Ed25519Signature),
        Secp256k1(Secp256k1Signature),
        Secp256r1(Secp256r1Signature),
        ZkLogin(ZkLoginAuthenticator),
    }

    #[derive(serde_derive::Serialize, serde_derive::Deserialize)]
    #[serde(tag = "scheme", rename_all = "lowercase")]
    #[serde(rename = "MultisigMemberSignature")]
    #[allow(clippy::large_enum_variant)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    enum ReadableMemberSignature {
        Ed25519 { signature: Ed25519Signature },
        Secp256k1 { signature: Secp256k1Signature },
        Secp256r1 { signature: Secp256r1Signature },
        ZkLogin(ZkLoginAuthenticator),
    }

    #[cfg(feature = "schemars")]
    impl schemars::JsonSchema for MultisigMemberSignature {
        fn schema_name() -> String {
            ReadableMemberSignature::schema_name()
        }

        fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
            ReadableMemberSignature::json_schema(gen)
        }
    }

    impl Serialize for MultisigMemberSignature {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = match self {
                    MultisigMemberSignature::Ed25519(signature) => {
                        ReadableMemberSignature::Ed25519 {
                            signature: *signature,
                        }
                    }
                    MultisigMemberSignature::Secp256k1(signature) => {
                        ReadableMemberSignature::Secp256k1 {
                            signature: *signature,
                        }
                    }
                    MultisigMemberSignature::Secp256r1(signature) => {
                        ReadableMemberSignature::Secp256r1 {
                            signature: *signature,
                        }
                    }
                    MultisigMemberSignature::ZkLogin(authenticator) => {
                        ReadableMemberSignature::ZkLogin(authenticator.clone())
                    }
                };
                readable.serialize(serializer)
            } else {
                let binary = match self {
                    MultisigMemberSignature::Ed25519(signature) => {
                        MemberSignature::Ed25519(*signature)
                    }
                    MultisigMemberSignature::Secp256k1(signature) => {
                        MemberSignature::Secp256k1(*signature)
                    }
                    MultisigMemberSignature::Secp256r1(signature) => {
                        MemberSignature::Secp256r1(*signature)
                    }
                    MultisigMemberSignature::ZkLogin(authenticator) => {
                        MemberSignature::ZkLogin(authenticator.clone())
                    }
                };
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for MultisigMemberSignature {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let readable = ReadableMemberSignature::deserialize(deserializer)?;
                Ok(match readable {
                    ReadableMemberSignature::Ed25519 { signature } => Self::Ed25519(signature),
                    ReadableMemberSignature::Secp256k1 { signature } => Self::Secp256k1(signature),
                    ReadableMemberSignature::Secp256r1 { signature } => Self::Secp256r1(signature),
                    ReadableMemberSignature::ZkLogin(authenticator) => Self::ZkLogin(authenticator),
                })
            } else {
                let binary = MemberSignature::deserialize(deserializer)?;
                Ok(match binary {
                    MemberSignature::Ed25519(signature) => Self::Ed25519(signature),
                    MemberSignature::Secp256k1(signature) => Self::Secp256k1(signature),
                    MemberSignature::Secp256r1(signature) => Self::Secp256r1(signature),
                    MemberSignature::ZkLogin(authenticator) => Self::ZkLogin(authenticator),
                })
            }
        }
    }
}
