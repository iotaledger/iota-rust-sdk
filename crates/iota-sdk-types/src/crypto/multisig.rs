// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// TODO sort out overlap with iota-sdk-crypto's multisig module

use std::{
    convert::Infallible,
    hash::{Hash, Hasher},
};

use base64ct::Encoding;
use once_cell::sync::OnceCell;

use super::{
    Ed25519PublicKey, Ed25519Signature, Secp256k1PublicKey, Secp256k1Signature, Secp256r1PublicKey,
    Secp256r1Signature, SignatureScheme,
    passkey::{PasskeyAuthenticator, PasskeyPublicKey},
};
use crate::PublicKeyExt;

pub type WeightUnit = u8;
pub type ThresholdUnit = u16;
pub type BitmapUnit = u16;

const MAX_COMMITTEE_SIZE: usize = 10;
// TODO validate sigs
const MAX_BITMAP_VALUE: BitmapUnit = 0b1111111111;

pub enum MultisigError {}

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
// TODO why is this not just PublicKey?
pub enum MultisigMemberPublicKey {
    Ed25519(Ed25519PublicKey),
    Secp256k1(Secp256k1PublicKey),
    Secp256r1(Secp256r1PublicKey),
    ZkLoginDeprecated,
    Passkey(PasskeyPublicKey),
}

impl MultisigMemberPublicKey {
    crate::def_is_as_into_opt!(
        Ed25519(Ed25519PublicKey),
        Secp256k1(Secp256k1PublicKey),
        Secp256r1(Secp256r1PublicKey),
        Passkey(PasskeyPublicKey),
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
            MultisigMemberPublicKey::ZkLoginDeprecated => {
                SignatureScheme::ZkLoginAuthenticatorDeprecated
            }
            MultisigMemberPublicKey::Passkey(passkey_public_key) => passkey_public_key.scheme(),
        }
    }

    pub fn to_base64(&self) -> String {
        base64ct::Base64::encode_string(self.as_ref())
    }
}

impl AsRef<[u8]> for MultisigMemberPublicKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Ed25519(pk) => pk.as_ref(),
            Self::Secp256k1(pk) => pk.as_ref(),
            Self::Secp256r1(pk) => pk.as_ref(),
            Self::ZkLogin(_) => panic!(),
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
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct MultisigMember {
    public_key: MultisigMemberPublicKey,
    weight: WeightUnit,
}

impl MultisigMember {
    /// Construct a new member from a `MultisigMemberPublicKey` and a `weight`.
    pub fn new(public_key: impl Into<MultisigMemberPublicKey>, weight: WeightUnit) -> Self {
        Self {
            public_key: public_key.into(),
            weight,
        }
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
    /// `threshold` without validating the result.
    ///
    /// Note that the order of the members is significant towards deriving the
    /// `Address` governed by this committee.
    pub fn insecure_new(members: Vec<MultisigMember>, threshold: ThresholdUnit) -> Self {
        Self { members, threshold }
    }

    /// Construct a new committee from a list of `MultisigMember`s and a
    /// `threshold`.
    ///
    /// Note that the order of the members is significant towards deriving the
    /// `Address` governed by this committee.
    pub fn new(members: Vec<MultisigMember>, threshold: ThresholdUnit) -> Result<Self, Infallible> {
        let committee = Self::insecure_new(members, threshold);

        if committee.is_valid() {
            Ok(committee)
        } else {
            panic!("Invalid multisig committee construction")

            // TODO
            //         return Err(IotaError::InvalidSignature {
            //     error: "Invalid multisig public key
            // construction".to_string(), });
        }
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

    /// Get the index of a public key in the committee, if it is a member.
    pub fn get_public_key_index(&self, pk: &MultisigMemberPublicKey) -> Option<u8> {
        self.members
            .iter()
            .position(|member| &member.public_key == pk)
            .map(|x| x as u8)
    }

    /// Checks if the Committee is valid.
    ///
    /// A valid committee is one that:
    ///  - Has a nonzero threshold
    ///  - Has at least one member
    ///  - Has at most ten members
    ///  - No member has weight 0
    ///  - the sum of the weights of all members must be at least the threshold
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
    /// A bytes representation of [struct MultiSig]. This helps with
    /// implementing [trait AsRef<[u8]>].
    #[cfg_attr(feature = "schemars", schemars(skip))]
    #[cfg_attr(
        feature = "proptest",
        strategy(proptest::strategy::Just(OnceCell::new()))
    )]
    bytes: OnceCell<Vec<u8>>,
}

impl MultisigAggregatedSignature {
    /// Construct a new aggregated multisig signature.
    ///
    /// Since the list of signatures doesn't contain sufficient information to
    /// identify which committee member provided the signature, it is up to
    /// the caller to ensure that the provided signature list is in the same
    /// order as it's corresponding member in the provided committee
    /// and that it's position in the provided bitmap is set.
    // TODO rename to insecure?
    pub fn new(
        signatures: Vec<MultisigMemberSignature>,
        bitmap: BitmapUnit,
        committee: MultisigCommittee,
    ) -> Self {
        Self {
            signatures,
            bitmap,
            committee,
            bytes: OnceCell::new(),
        }
    }

    /// This combines a list of [enum Signature] `flag || signature || pk` to a
    /// MultiSig. The order of full_sigs must be the same as the order of
    /// public keys in [enum MultiSigPublicKey]. e.g. for [pk1, pk2, pk3,
    /// pk4, pk5], [sig1, sig2, sig5] is valid, but [sig2, sig1, sig5] is
    /// invalid.
    // TODO keep this name or rename to new?
    pub fn combine(
        signatures: Vec<MultisigMemberSignature>,
        committee: MultisigCommittee,
    ) -> Result<Self, MultisigError> {
        // TODO call is_valid?
        if !committee.is_valid() {
            //     .map_err(|_| MultisigError::InvalidSignature {
            //     error: "Invalid multisig public key".to_string(),
            // })?;
        }

        if signatures.len() > committee.members.len() || signatures.is_empty() {
            // return Err(MultisigError::InvalidSignature {
            //     error: "Invalid number of signatures".to_string(),
            // });
        }

        let mut bitmap = 0;
        // TODO do we actually need this vec?
        let mut sigs = Vec::with_capacity(signatures.len());
        for signature in signatures {
            let pk = signature.to_public_key()?;
            let index = committee.get_public_key_index(&pk).unwrap();
            // .ok_or(MultisigError::IncorrectSigner {
            //     error: format!("pk does not exist: {pk:?}"),
            // })?;
            if bitmap & (1 << index) != 0 {
                // return Err(MultisigError::InvalidSignature {
                //     error: "Duplicate public key".to_string(),
                // });
            }
            bitmap |= 1 << index;
            sigs.push(signature);
        }

        Ok(MultisigAggregatedSignature {
            signatures: sigs,
            bitmap,
            committee,
            bytes: OnceCell::new(),
        })
    }

    pub fn is_valid(&self) -> bool {
        if self.signatures.len() > self.committee.members.len()
            || self.signatures.is_empty()
            || self.bitmap > MAX_BITMAP_VALUE
        {
            return false;
        }
        self.committee.is_valid()
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

    pub fn has_scheme_signatures(&self, scheme: SignatureScheme) -> bool {
        self.signatures.iter().any(|s| s.scheme() == scheme)
    }

    // TODO meh, returns a generic thing
    pub fn get_scheme_signatures(&self, scheme: SignatureScheme) -> Vec<MultisigMemberSignature> {
        self.signatures
            .iter()
            .filter(|s| s.scheme() == scheme)
            .cloned()
            .collect()
    }
}

impl PartialEq for MultisigAggregatedSignature {
    fn eq(&self, other: &Self) -> bool {
        self.bitmap == other.bitmap
            && self.committee == other.committee
            && self.signatures == other.signatures
    }
}

impl Eq for MultisigAggregatedSignature {}

/// This initialize the underlying bytes representation of MultiSig.
/// It encodes [struct MultiSig] as the MultiSig flag (0x03) concat with the bcs
/// bytes of [struct MultiSig] i.e. `flag || bcs_bytes(MultiSig)`.
impl AsRef<[u8]> for MultisigAggregatedSignature {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            // TODO Infallible?
            .get_or_try_init::<_, Infallible>(|| {
                let as_bytes = bcs::to_bytes(self).expect("BCS serialization should not fail");
                let mut bytes = Vec::with_capacity(1 + as_bytes.len());
                bytes.push(SignatureScheme::Multisig as u8);
                bytes.extend_from_slice(as_bytes.as_slice());
                Ok(bytes)
            })
            .expect("OnceCell invariant violated")
    }
}

impl Hash for MultisigAggregatedSignature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

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
///                             zklogin-multisig-member-signature-deprecated /
///                             passkey-multisig-member-signature
///
/// ed25519-multisig-member-signature               = %d00 ed25519-signature
/// secp256k1-multisig-member-signature             = %d01 secp256k1-signature
/// secp256r1-multisig-member-signature             = %d02 secp256r1-signature
/// zklogin-multisig-member-signature-deprecated    = %d03
/// passkey-multisig-member-signature               = %d04 passkey-authenticator
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[non_exhaustive]
// TODO why not a regular signature?
pub enum MultisigMemberSignature {
    Ed25519(Ed25519Signature),
    Secp256k1(Secp256k1Signature),
    Secp256r1(Secp256r1Signature),
    ZkLoginDeprecated,
    Passkey(PasskeyAuthenticator),
}

impl MultisigMemberSignature {
    crate::def_is_as_into_opt!(
        Ed25519(Ed25519Signature),
        Secp256k1(Secp256k1Signature),
        Secp256r1(Secp256r1Signature),
        Passkey(PasskeyAuthenticator),
    );

    fn to_public_key(&self) -> Result<MultisigMemberPublicKey, MultisigError> {
        panic!();
        //     match self {
        //         Self::Ed25519(sig) =>
        // Ok(MultisigMemberPublicKey::Ed25519(sig.to_public_key())),
        //         Self::Secp256k1(sig) =>
        // Ok(MultisigMemberPublicKey::Secp256k1(sig.to_public_key())),
        //         Self::Secp256r1(sig) =>
        // Ok(MultisigMemberPublicKey::Secp256r1(sig.to_public_key())),
        //         Self::ZkLogin(authenticator) =>
        // Ok(MultisigMemberPublicKey::ZkLogin(
        // authenticator.to_public_identifier(),         )),
        //     }
    }

    pub fn scheme(&self) -> SignatureScheme {
        match self {
            Self::Ed25519(_) => SignatureScheme::Ed25519,
            Self::Secp256k1(_) => SignatureScheme::Secp256k1,
            Self::Secp256r1(_) => SignatureScheme::Secp256r1,
            Self::ZkLogin(_) => SignatureScheme::ZkLoginAuthenticator,
        }
    }
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
    // TODO is this really needed?
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
                    bytes: OnceCell::new(),
                })
            } else {
                let bytes: Cow<'de, [u8]> = Bytes::deserialize_as(deserializer)?;
                Self::from_bytes(bytes).map_err(serde::de::Error::custom)
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

        pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, SignatureFromBytesError> {
            let bytes = bytes.as_ref();
            let flag =
                SignatureScheme::from_byte(*bytes.first().ok_or_else(|| {
                    SignatureFromBytesError::new("missing signature scheme flag")
                })?)
                .map_err(SignatureFromBytesError::new)?;

            if flag != SignatureScheme::Multisig {
                return Err(SignatureFromBytesError::new("invalid multisig flag"));
            }

            if let Ok(multisig) = bcs::from_bytes::<Multisig>(&bytes[1..]) {
                let multisig = Self {
                    signatures: multisig.signatures,
                    bitmap: multisig.bitmap,
                    committee: multisig.committee,
                    bytes: OnceCell::new(),
                };
                if multisig.is_valid() {
                    Ok(multisig)
                } else {
                    Err(SignatureFromBytesError::new("invalid multisig"))
                }
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
        ZkLoginDeprecated,
        Passkey(PasskeyPublicKey),
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(tag = "scheme", rename_all = "lowercase")]
    #[serde(rename = "MultisigMemberPublicKey")]
    enum ReadableMemberPublicKey {
        Ed25519 { public_key: Ed25519PublicKey },
        Secp256k1 { public_key: Secp256k1PublicKey },
        Secp256r1 { public_key: Secp256r1PublicKey },
        ZkLoginDeprecated,
        Passkey { public_key: PasskeyPublicKey },
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
                    MultisigMemberPublicKey::ZkLoginDeprecated => {
                        ReadableMemberPublicKey::ZkLoginDeprecated
                    }
                    MultisigMemberPublicKey::Passkey(public_key) => {
                        ReadableMemberPublicKey::Passkey {
                            public_key: public_key.clone(),
                        }
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
                    MultisigMemberPublicKey::ZkLoginDeprecated => {
                        MemberPublicKey::ZkLoginDeprecated
                    }
                    MultisigMemberPublicKey::Passkey(public_key) => {
                        MemberPublicKey::Passkey(public_key.clone())
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
                    ReadableMemberPublicKey::ZkLoginDeprecated => Self::ZkLoginDeprecated,
                    ReadableMemberPublicKey::Passkey { public_key } => Self::Passkey(public_key),
                })
            } else {
                let binary = MemberPublicKey::deserialize(deserializer)?;
                Ok(match binary {
                    MemberPublicKey::Ed25519(public_key) => Self::Ed25519(public_key),
                    MemberPublicKey::Secp256k1(public_key) => Self::Secp256k1(public_key),
                    MemberPublicKey::Secp256r1(public_key) => Self::Secp256r1(public_key),
                    MemberPublicKey::ZkLoginDeprecated => Self::ZkLoginDeprecated,
                    MemberPublicKey::Passkey(public_key) => Self::Passkey(public_key),
                })
            }
        }
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    enum MemberSignature {
        Ed25519(Ed25519Signature),
        Secp256k1(Secp256k1Signature),
        Secp256r1(Secp256r1Signature),
        ZkLoginDeprecated,
        Passkey(PasskeyAuthenticator),
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(tag = "scheme", rename_all = "lowercase")]
    #[serde(rename = "MultisigMemberSignature")]
    enum ReadableMemberSignature {
        Ed25519 { signature: Ed25519Signature },
        Secp256k1 { signature: Secp256k1Signature },
        Secp256r1 { signature: Secp256r1Signature },
        ZkLoginDeprecated,
        Passkey(PasskeyAuthenticator),
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
                    MultisigMemberSignature::ZkLoginDeprecated => {
                        ReadableMemberSignature::ZkLoginDeprecated
                    }
                    MultisigMemberSignature::Passkey(authenticator) => {
                        ReadableMemberSignature::Passkey(authenticator.clone())
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
                    MultisigMemberSignature::ZkLoginDeprecated => {
                        MemberSignature::ZkLoginDeprecated
                    }
                    MultisigMemberSignature::Passkey(authenticator) => {
                        MemberSignature::Passkey(authenticator.clone())
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
                    ReadableMemberSignature::ZkLoginDeprecated => Self::ZkLoginDeprecated,
                    ReadableMemberSignature::Passkey(authenticator) => Self::Passkey(authenticator),
                })
            } else {
                let binary = MemberSignature::deserialize(deserializer)?;
                Ok(match binary {
                    MemberSignature::Ed25519(signature) => Self::Ed25519(signature),
                    MemberSignature::Secp256k1(signature) => Self::Secp256k1(signature),
                    MemberSignature::Secp256r1(signature) => Self::Secp256r1(signature),
                    MemberSignature::ZkLoginDeprecated => Self::ZkLoginDeprecated,
                    MemberSignature::Passkey(authenticator) => Self::Passkey(authenticator),
                })
            }
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;
    use crate::UserSignature;

    /// Roundtrip a multisig committee and aggregated signature that include a
    /// passkey member.
    #[test]
    fn passkey_multisig_roundtrip() {
        let passkey_b64 = "BiVYDmenOnqS+thmz5m5SrZnWaKXZLVxgh+rri6LHXs25B0AAAAAnQF7InR5cGUiOiJ3ZWJhdXRobi5nZXQiLCAiY2hhbGxlbmdlIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTE3MyIsImNyb3NzT3JpZ2luIjpmYWxzZSwgInVua25vd24iOiAidW5rbm93biJ9YgJMwqcOmZI7F/N+K5SMe4DRYCb4/cDWW68SFneSHoD2GxKKhksbpZ5rZpdrjSYABTCsFQQBpLORzTvbj4edWKd/AsEBeovrGvHR9Ku7critg6k7qvfFlPUngujXfEzXd8Eg";
        let UserSignature::PasskeyAuthenticator(passkey_authenticator) =
            UserSignature::from_base64(passkey_b64).unwrap()
        else {
            panic!("expected passkey authenticator");
        };

        let passkey_pk = passkey_authenticator.public_key();
        let committee = MultisigCommittee::new(
            vec![MultisigMember::new(
                MultisigMemberPublicKey::Passkey(passkey_pk),
                1,
            )],
            1,
        );
        assert!(committee.is_valid());

        let aggregated = MultisigAggregatedSignature::new(
            committee,
            vec![MultisigMemberSignature::Passkey(passkey_authenticator)],
            0b1,
        );

        let bcs_bytes = bcs::to_bytes(&aggregated).unwrap();
        let from_bcs: MultisigAggregatedSignature = bcs::from_bytes(&bcs_bytes).unwrap();
        assert_eq!(aggregated, from_bcs);

        let json = serde_json::to_string(&aggregated).unwrap();
        let from_json: MultisigAggregatedSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(aggregated, from_json);
    }

    /// The passkey tag in the `MultisigMemberPublicKey` BCS enum must be
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

        let pk = MultisigMemberPublicKey::Passkey(passkey_authenticator.public_key());
        let bcs_bytes = bcs::to_bytes(&pk).unwrap();
        assert_eq!(bcs_bytes[0], 0x04, "passkey must use BCS tag 0x04");
        // 1 tag byte + 33 bytes for the secp256r1 compressed public key.
        assert_eq!(bcs_bytes.len(), 34);
    }
}
