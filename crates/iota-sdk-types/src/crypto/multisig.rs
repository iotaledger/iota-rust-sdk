// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{
    Ed25519PublicKey, Ed25519Signature, Secp256k1PublicKey, Secp256k1Signature, Secp256r1PublicKey,
    Secp256r1Signature, SignatureScheme,
    zklogin::{ZkLoginAuthenticator, ZkLoginPublicIdentifier},
};
use crate::PublicKeyExt;

pub type WeightUnit = u8;
pub type ThresholdUnit = u16;
pub type BitmapUnit = u16;

const MAX_COMMITTEE_SIZE: usize = 10;
// TODO validate sigs
// const MAX_BITMAP_VALUE: BitmapUnit = 0b1111111111;

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
///                              zklogin-multisig-member-public-key
///
/// ed25519-multisig-member-public-key   = %x00 ed25519-public-key
/// secp256k1-multisig-member-public-key = %x01 secp256k1-public-key
/// secp256r1-multisig-member-public-key = %x02 secp256r1-public-key
/// zklogin-multisig-member-public-key   = %x03 zklogin-public-identifier
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
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub enum MultisigMemberPublicKey {
    Ed25519(Ed25519PublicKey),
    Secp256k1(Secp256k1PublicKey),
    Secp256r1(Secp256r1PublicKey),
    ZkLogin(ZkLoginPublicIdentifier),
}

impl MultisigMemberPublicKey {
    crate::def_is_as_into_opt!(
        Ed25519(Ed25519PublicKey),
        Secp256k1(Secp256k1PublicKey),
        Secp256r1(Secp256r1PublicKey),
        ZkLogin as zklogin(ZkLoginPublicIdentifier),
    );

    pub fn scheme(&self) -> SignatureScheme {
        match self {
            MultisigMemberPublicKey::Ed25519(ed25519_public_key) => ed25519_public_key.scheme(),
            MultisigMemberPublicKey::Secp256k1(secp256k1_public_key) => {
                secp256k1_public_key.scheme()
            }
            MultisigMemberPublicKey::Secp256r1(secp256r1_public_key) => {
                secp256r1_public_key.scheme()
            }
            MultisigMemberPublicKey::ZkLogin(zk_login_public_identifier) => {
                zk_login_public_identifier.scheme()
            }
        }
    }
}

/// A member in a multisig committee
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// multisig-member = multisig-member-public-key
///                   u8    ; weight
/// ```
///
/// There is also a legacy encoding for this type defined as:
///
/// ```text
/// legacy-multisig-member = legacy-multisig-member-public-key
///                          u8     ; weight
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct MultisigMember {
    public_key: MultisigMemberPublicKey,
    weight: WeightUnit,
}

impl MultisigMember {
    /// Construct a new member from a `MultisigMemberPublicKey` and a `weight`.
    pub fn new(public_key: MultisigMemberPublicKey, weight: WeightUnit) -> Self {
        Self { public_key, weight }
    }

    /// This member's public key.
    pub fn public_key(&self) -> &MultisigMemberPublicKey {
        &self.public_key
    }

    /// Weight of this member's signature.
    pub fn weight(&self) -> WeightUnit {
        self.weight
    }
}

/// A multisig committee
///
/// A `MultisigCommittee` is a set of members who collectively control a single
/// `Address` on the IOTA blockchain. The number of required signatures to
/// authorize the execution of a transaction is determined by
/// `(signature_0_weight + signature_1_weight ..) >= threshold`.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// multisig-committee = (vector multisig-member)
///                      u16    ; threshold
/// ```
///
/// There is also a legacy encoding for this type defined as:
///
/// ```text
/// legacy-multisig-committee = (vector legacy-multisig-member)
///                             u16     ; threshold
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct MultisigCommittee {
    /// A list of committee members and their corresponding weight.
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=10).lift()))]
    members: Vec<MultisigMember>,
    /// If the total weight of the public keys corresponding to verified
    /// signatures is larger than threshold, the Multisig is verified.
    threshold: ThresholdUnit,
}

impl MultisigCommittee {
    /// Construct a new committee from a list of `MultisigMember`s and a
    /// `threshold`.
    ///
    /// Note that the order of the members is significant towards deriving the
    /// `Address` governed by this committee.
    pub fn new(members: Vec<MultisigMember>, threshold: ThresholdUnit) -> Self {
        Self { members, threshold }
    }

    /// The members of the committee
    pub fn members(&self) -> &[MultisigMember] {
        &self.members
    }

    /// The total signature weight required to authorize a transaction for the
    /// address corresponding to this `MultisigCommittee`.
    pub fn threshold(&self) -> ThresholdUnit {
        self.threshold
    }

    /// Return the flag for this signature scheme
    pub fn scheme(&self) -> SignatureScheme {
        SignatureScheme::Multisig
    }

    /// Checks if the Committee is valid.
    ///
    /// A valid committee is one that:
    ///  - Has a nonzero threshold
    ///  - Has at least one member
    ///  - Has at most ten members
    ///  - No member has weight 0
    ///  - the sum of the weights of all members must be larger than the
    ///    threshold
    ///  - contains no duplicate members
    pub fn is_valid(&self) -> bool {
        self.threshold != 0
            && !self.members.is_empty()
            && self.members.len() <= MAX_COMMITTEE_SIZE
            && !self.members.iter().any(|member| member.weight == 0)
            && self
                .members
                .iter()
                .map(|member| member.weight as ThresholdUnit)
                .sum::<ThresholdUnit>()
                >= self.threshold
            && !self.members.iter().enumerate().any(|(i, member)| {
                self.members
                    .iter()
                    .skip(i + 1)
                    .any(|m| member.public_key == m.public_key)
            })
    }
}

/// Aggregated signature from members of a multisig committee.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// multisig-aggregated-signature = (vector multisig-member-signature)
///                                 u16     ; bitmap
///                                 multisig-committee
/// ```
///
/// There is also a legacy encoding for this type defined as:
///
/// ```text
/// legacy-multisig-aggregated-signature = (vector multisig-member-signature)
///                                        roaring-bitmap   ; bitmap
///                                        legacy-multisig-committee
/// roaring-bitmap = bytes  ; where the contents of the bytes are valid
///                         ; according to the serialized spec for
///                         ; roaring bitmaps
/// ```
///
/// See [here](https://github.com/RoaringBitmap/RoaringFormatSpec) for the specification for the
/// serialized format of RoaringBitmaps.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct MultisigAggregatedSignature {
    /// The plain signature encoded with signature scheme.
    ///
    /// The signatures must be in the same order as they are listed in the
    /// committee.
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=10).lift()))]
    signatures: Vec<MultisigMemberSignature>,
    /// A bitmap that indicates the position of which public key the signature
    /// should be authenticated with.
    bitmap: BitmapUnit,
    /// The public key encoded with each public key with its signature scheme
    /// used along with the corresponding weight.
    committee: MultisigCommittee,
}

impl MultisigAggregatedSignature {
    /// Construct a new aggregated multisig signature.
    ///
    /// Since the list of signatures doesn't contain sufficient information to
    /// identify which committee member provided the signature, it is up to
    /// the caller to ensure that the provided signature list is in the same
    /// order as it's corresponding member in the provided committee
    /// and that it's position in the provided bitmap is set.
    pub fn new(
        committee: MultisigCommittee,
        signatures: Vec<MultisigMemberSignature>,
        bitmap: BitmapUnit,
    ) -> Self {
        Self {
            signatures,
            bitmap,
            committee,
        }
    }

    /// The list of signatures from committee members
    pub fn signatures(&self) -> &[MultisigMemberSignature] {
        &self.signatures
    }

    /// The bitmap that indicates which committee members provided their
    /// signature.
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

/// A signature from a member of a multisig committee.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// multisig-member-signature = ed25519-multisig-member-signature /
///                             secp256k1-multisig-member-signature /
///                             secp256r1-multisig-member-signature /
///                             zklogin-multisig-member-signature
///
/// ed25519-multisig-member-signature   = %x00 ed25519-signature
/// secp256k1-multisig-member-signature = %x01 secp256k1-signature
/// secp256r1-multisig-member-signature = %x02 secp256r1-signature
/// zklogin-multisig-member-signature   = %x03 zklogin-authenticator
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub enum MultisigMemberSignature {
    Ed25519(Ed25519Signature),
    Secp256k1(Secp256k1Signature),
    Secp256r1(Secp256r1Signature),
    ZkLogin(Box<ZkLoginAuthenticator>),
}

impl MultisigMemberSignature {
    crate::def_is_as_into_opt!(
        Ed25519(Ed25519Signature),
        Secp256k1(Secp256k1Signature),
        Secp256r1(Secp256r1Signature),
        ZkLogin as zklogin(Box<ZkLoginAuthenticator>)
    );
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization {
    use std::borrow::Cow;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::{Bytes, DeserializeAs};

    use super::*;
    use crate::{
        Ed25519PublicKey, Secp256k1PublicKey, Secp256r1PublicKey, SignatureScheme,
        crypto::SignatureFromBytesError,
    };

    #[derive(serde::Deserialize)]
    pub struct Multisig {
        signatures: Vec<MultisigMemberSignature>,
        bitmap: BitmapUnit,
        committee: MultisigCommittee,
    }

    #[derive(serde::Serialize)]
    pub struct MultisigRef<'a> {
        signatures: &'a [MultisigMemberSignature],
        bitmap: BitmapUnit,
        committee: &'a MultisigCommittee,
    }

    #[derive(serde::Deserialize)]
    struct ReadableMultisigAggregatedSignature {
        signatures: Vec<MultisigMemberSignature>,
        bitmap: BitmapUnit,
        committee: MultisigCommittee,
    }

    #[derive(serde::Serialize)]
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
                let bytes = self.to_bytes();
                serializer.serialize_bytes(&bytes)
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
                Self::from_serialized_bytes(bytes).map_err(serde::de::Error::custom)
            }
        }
    }

    impl MultisigAggregatedSignature {
        pub(crate) fn to_bytes(&self) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.push(SignatureScheme::Multisig as u8);

            let multisig = MultisigRef {
                signatures: &self.signatures,
                bitmap: self.bitmap,
                committee: &self.committee,
            };
            bcs::serialize_into(&mut buf, &multisig).expect("serialization cannot fail");
            buf
        }

        pub fn from_serialized_bytes(
            bytes: impl AsRef<[u8]>,
        ) -> Result<Self, SignatureFromBytesError> {
            let bytes = bytes.as_ref();
            let flag =
                SignatureScheme::from_byte(*bytes.first().ok_or_else(|| {
                    SignatureFromBytesError::new("missing signature scheme flag")
                })?)
                .map_err(SignatureFromBytesError::new)?;
            if flag != SignatureScheme::Multisig {
                return Err(SignatureFromBytesError::new("invalid multisig flag"));
            }
            let bcs_bytes = &bytes[1..];

            if let Ok(multisig) = bcs::from_bytes::<Multisig>(bcs_bytes) {
                Ok(Self {
                    signatures: multisig.signatures,
                    bitmap: multisig.bitmap,
                    committee: multisig.committee,
                })
            } else {
                Err(SignatureFromBytesError::new("invalid multisig"))
            }
        }
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    enum MemberPublicKey {
        Ed25519(Ed25519PublicKey),
        Secp256k1(Secp256k1PublicKey),
        Secp256r1(Secp256r1PublicKey),
        ZkLogin(ZkLoginPublicIdentifier),
    }

    #[derive(serde::Serialize, serde::Deserialize)]
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

    #[derive(serde::Serialize, serde::Deserialize)]
    enum MemberSignature {
        Ed25519(Ed25519Signature),
        Secp256k1(Secp256k1Signature),
        Secp256r1(Secp256r1Signature),
        ZkLogin(Box<ZkLoginAuthenticator>),
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(tag = "scheme", rename_all = "lowercase")]
    #[serde(rename = "MultisigMemberSignature")]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    enum ReadableMemberSignature {
        Ed25519 { signature: Ed25519Signature },
        Secp256k1 { signature: Secp256k1Signature },
        Secp256r1 { signature: Secp256r1Signature },
        ZkLogin(Box<ZkLoginAuthenticator>),
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
