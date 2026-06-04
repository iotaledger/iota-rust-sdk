// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "serde")]
use std::sync::OnceLock;

#[cfg(feature = "serde")]
use super::SignatureFromBytesError;
use super::{
    Ed25519Signature, PublicKey, Secp256k1Signature, Secp256r1Signature, SignatureScheme,
    SimpleSignature, passkey::PasskeyAuthenticator,
};
use crate::UserSignature;

pub type WeightUnit = u8;
pub type ThresholdUnit = u16;
pub type BitmapUnit = u16;

pub const MULTISIG_COMMITTEE_SIZE_MAX: usize = 10;
pub const MULTISIG_BITMAP_VALUE_MAX: BitmapUnit = 0b1111111111;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MultisigError {
    #[error("{0}")]
    TryFromSlice(#[from] std::array::TryFromSliceError),
    #[error("{0}")]
    Base64(#[from] base64ct::Error),
    #[cfg(feature = "serde")]
    #[error("{0}")]
    SignatureFromBytes(#[from] SignatureFromBytesError),
    #[error("Multisig threshold must be non-zero")]
    ZeroThreshold,
    #[error("Multisig committee must have at least one member")]
    EmptyCommittee,
    #[error(
        "Multisig committee size {0} exceeds maximum size of {MULTISIG_COMMITTEE_SIZE_MAX} members"
    )]
    CommitteeTooLarge(usize),
    #[error("Multisig committee contains a member with zero weight")]
    ZeroWeightMember,
    #[error("Insufficient total weight {0} for threshold {1}")]
    InsufficientWeight(ThresholdUnit, ThresholdUnit),
    #[error("UnallowedSignatureType")]
    UnallowedSignatureType,
    #[error("Invalid input")]
    InvalidInput,
    #[error("Duplicate public key")]
    DuplicatePublicKey,
    #[error("Signatures are not in committee order")]
    SignaturesOutOfOrder,
    #[error("No public key found for signature at index: {0}")]
    NoPublicKeyForSignature(usize),
    #[error("Invalid number of signatures")]
    InvalidSignatureNumber,
    #[error("Invalid bitmap value: {0}")]
    InvalidBitmap(u16),
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
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct MultisigMember {
    public_key: PublicKey,
    weight: WeightUnit,
}

impl MultisigMember {
    /// Construct a new member from a [`PublicKey`] and a [`WeightUnit`].
    pub fn new(public_key: impl Into<PublicKey>, weight: WeightUnit) -> Self {
        Self {
            public_key: public_key.into(),
            weight,
        }
    }

    /// This member's public key.
    pub fn public_key(&self) -> &PublicKey {
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
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct MultisigCommittee {
    /// A list of committee members and their corresponding weight.
    members: Vec<MultisigMember>,
    /// If the total weight of the public keys corresponding to verified
    /// signatures is larger than threshold, the Multisig is verified.
    threshold: ThresholdUnit,
}

impl MultisigCommittee {
    /// Construct a [`MultisigCommittee`] without validating the result.
    ///
    /// Unlike [`Self::new`], this performs no checks: the committee may
    /// violate any of the invariants enforced by [`Self::validate`] (zero
    /// threshold, empty or oversized member list, zero-weight members,
    /// duplicate public keys, or a threshold exceeding the sum of weights).
    ///
    /// Note that the order of the members is significant towards deriving the
    /// [`Address`] governed by this committee.
    ///
    /// Prefer [`Self::new`]; this constructor is intended for deserialization
    /// paths and tests where the inputs are already known to be well-formed.
    ///
    /// [`Address`]: crate::Address
    pub fn new_unchecked(members: Vec<MultisigMember>, threshold: ThresholdUnit) -> Self {
        Self { members, threshold }
    }

    /// Construct a [`MultisigCommittee`] and verify it via [`Self::validate`].
    ///
    /// Compared to [`Self::new_unchecked`], this rejects committees that:
    ///  - have a zero `threshold`;
    ///  - contain zero or more than ten members;
    ///  - contain a member with weight 0;
    ///  - have a `threshold` greater than the sum of all member weights;
    ///  - contain duplicate public keys.
    ///
    /// Note that the order of the members is significant towards deriving the
    /// [`Address`] governed by this committee.
    ///
    /// [`Address`]: crate::Address
    pub fn new(
        members: Vec<MultisigMember>,
        threshold: ThresholdUnit,
    ) -> Result<Self, MultisigError> {
        let committee = Self::new_unchecked(members, threshold);

        committee.validate()?;

        Ok(committee)
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
    pub fn get_public_key_index(&self, pk: &PublicKey) -> Option<u8> {
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
    pub fn validate(&self) -> Result<(), MultisigError> {
        if self.threshold == 0 {
            return Err(MultisigError::ZeroThreshold);
        }
        if self.members.is_empty() {
            return Err(MultisigError::EmptyCommittee);
        }
        if self.members.len() > MULTISIG_COMMITTEE_SIZE_MAX {
            return Err(MultisigError::CommitteeTooLarge(self.members.len()));
        }
        if self.members.iter().any(|member| member.weight == 0) {
            return Err(MultisigError::ZeroWeightMember);
        }
        let total_weight: ThresholdUnit = self
            .members
            .iter()
            .map(|member| member.weight as ThresholdUnit)
            .sum();
        if total_weight < self.threshold {
            return Err(MultisigError::InsufficientWeight(
                total_weight,
                self.threshold,
            ));
        }
        for (i, member) in self.members.iter().enumerate() {
            if self
                .members
                .iter()
                .skip(i + 1)
                .any(|m| m.public_key == member.public_key)
            {
                return Err(MultisigError::DuplicatePublicKey);
            }
        }

        Ok(())
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
#[derive(Clone, Debug)]
pub struct MultisigAggregatedSignature {
    /// The plain signature encoded with signature scheme.
    ///
    /// The signatures must be in the same order as they are listed in the
    /// committee.
    signatures: Vec<MultisigMemberSignature>,
    /// A bitmap that indicates the position of which public key the signature
    /// should be authenticated with.
    bitmap: BitmapUnit,
    /// The public key encoded with each public key with its signature scheme
    /// used along with the corresponding weight.
    committee: MultisigCommittee,
    /// A bytes representation of this aggregated signature. This helps with
    /// implementing [trait AsRef<[u8]>].
    #[cfg(feature = "serde")]
    bytes: OnceLock<Vec<u8>>,
}

impl MultisigAggregatedSignature {
    /// Construct a [`MultisigAggregatedSignature`] from its raw parts without
    /// validation.
    ///
    /// Unlike [`Self::new`], this performs no checks: the `committee` is not
    /// validated, the `bitmap` is trusted as-is, and the signatures are not
    /// cross-referenced against the committee. The resulting value may be
    /// rejected by [`Self::validate`] or by on-chain verification.
    ///
    /// The caller must ensure that:
    ///  - `signatures` appear in the same order as their corresponding members
    ///    in `committee` (e.g. for committee `[pk1, pk2, pk3, pk4, pk5]`, valid
    ///    signature orderings include `[sig1, sig2, sig5]` but not `[sig2,
    ///    sig1, sig5]`);
    ///  - each contributing member's position is set in `bitmap`;
    ///  - `committee` itself satisfies [`MultisigCommittee::validate`].
    ///
    /// Prefer [`Self::new`] when starting from [`UserSignature`]s; this
    /// constructor is intended for deserialization paths and tests where the
    /// inputs are already known to be well-formed.
    pub fn new_unchecked(
        signatures: Vec<MultisigMemberSignature>,
        bitmap: BitmapUnit,
        committee: MultisigCommittee,
    ) -> Self {
        Self {
            signatures,
            bitmap,
            committee,
            #[cfg(feature = "serde")]
            bytes: OnceLock::new(),
        }
    }

    /// Construct a [`MultisigAggregatedSignature`] from a list of
    /// [`UserSignature`]s and a [`MultisigCommittee`].
    ///
    /// Compared to [`Self::new_unchecked`], this:
    ///  - validates `committee` via [`MultisigCommittee::validate`];
    ///  - converts each [`UserSignature`] into a [`MultisigMemberSignature`];
    ///  - derives the `bitmap` by locating each signature's public key in the
    ///    committee, rejecting duplicates and signatures from non-members;
    ///  - rejects empty signature lists and lists longer than the committee;
    ///  - rejects `signatures` that are not in committee order.
    ///
    /// `signatures` must appear in the same order as their corresponding
    /// members in `committee`: for committee `[pk1, pk2, pk3, pk4, pk5]`,
    /// `[sig1, sig2, sig5]` is accepted but `[sig2, sig1, sig5]` is rejected
    /// with [`MultisigError::SignaturesOutOfOrder`].
    pub fn new(
        signatures: Vec<UserSignature>,
        committee: MultisigCommittee,
    ) -> Result<Self, MultisigError> {
        if signatures.len() > committee.members.len() || signatures.is_empty() {
            return Err(MultisigError::InvalidSignatureNumber);
        }

        committee.validate()?;

        let mut bitmap = 0;
        let mut member_signatures = Vec::with_capacity(signatures.len());
        let mut prev_index: Option<u8> = None;
        for (sig_index, signature) in signatures.into_iter().enumerate() {
            let pk = signature
                .to_public_key()
                .map_err(|_| MultisigError::UnallowedSignatureType)?;
            let index = committee
                .get_public_key_index(&pk)
                .ok_or(MultisigError::NoPublicKeyForSignature(sig_index))?;
            if bitmap & (1 << index) != 0 {
                return Err(MultisigError::DuplicatePublicKey);
            }
            if let Some(prev) = prev_index
                && index < prev
            {
                return Err(MultisigError::SignaturesOutOfOrder);
            }
            bitmap |= 1 << index;
            prev_index = Some(index);
            member_signatures.push(signature.try_into()?);
        }

        let signature = MultisigAggregatedSignature {
            signatures: member_signatures,
            bitmap,
            committee,
            #[cfg(feature = "serde")]
            bytes: OnceLock::new(),
        };

        Ok(signature)
    }

    /// Validates the structural integrity of this aggregated signature.
    pub fn validate(&self) -> Result<(), MultisigError> {
        self.committee.validate()?;

        if self.signatures.len() > self.committee.members.len() || self.signatures.is_empty() {
            return Err(MultisigError::InvalidSignatureNumber);
        }

        let bits_past_committee = self
            .bitmap
            .checked_shr(self.committee.members.len() as u32)
            .unwrap_or(0);
        if bits_past_committee != 0 || self.signatures.len() != self.bitmap.count_ones() as usize {
            return Err(MultisigError::InvalidBitmap(self.bitmap));
        }

        Ok(())
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

    /// The indices of the committee members that provided their signature,
    /// derived from the [`bitmap`](Self::bitmap).
    ///
    /// For example, a bitmap of `0b10110` yields `[1, 2, 4]`. Returns
    /// [`MultisigError::InvalidBitmap`] if the bitmap has bits set beyond the
    /// maximum committee size.
    pub fn indices(&self) -> Result<Vec<u8>, MultisigError> {
        as_indices(self.bitmap)
    }

    /// The committee that authorizes this aggregated signature.
    pub fn committee(&self) -> &MultisigCommittee {
        &self.committee
    }

    /// Returns `true` if any of the member signatures uses the given signature
    /// scheme.
    pub fn contains_signature_scheme(&self, scheme: SignatureScheme) -> bool {
        self.signatures.iter().any(|s| s.scheme() == scheme)
    }
}

/// Interpret a bitmap of 01s as a list of indices that is set to 1s.
/// e.g. 22 = 0b10110, then the result is [1, 2, 4].
fn as_indices(bitmap: u16) -> Result<Vec<u8>, MultisigError> {
    if bitmap > MULTISIG_BITMAP_VALUE_MAX {
        return Err(MultisigError::InvalidBitmap(bitmap));
    }
    let mut res = Vec::new();
    for i in 0..MULTISIG_COMMITTEE_SIZE_MAX {
        if bitmap & (1 << i) != 0 {
            res.push(i as u8);
        }
    }
    Ok(res)
}

impl PartialEq for MultisigAggregatedSignature {
    fn eq(&self, other: &Self) -> bool {
        self.bitmap == other.bitmap
            && self.committee == other.committee
            && self.signatures == other.signatures
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
///                             passkey-multisig-member-signature
///
/// ed25519-multisig-member-signature               = %d00 ed25519-signature
/// secp256k1-multisig-member-signature             = %d01 secp256k1-signature
/// secp256r1-multisig-member-signature             = %d02 secp256r1-signature
/// passkey-multisig-member-signature               = %d04 passkey-authenticator
/// ```
#[derive(Clone, Debug, derive_more::From, Eq, PartialEq)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[non_exhaustive]
pub enum MultisigMemberSignature {
    Ed25519(Ed25519Signature),
    Secp256k1(Secp256k1Signature),
    Secp256r1(Secp256r1Signature),
    Passkey(PasskeyAuthenticator),
}

impl MultisigMemberSignature {
    crate::def_is_as_into_opt!(
        Ed25519(Ed25519Signature),
        Secp256k1(Secp256k1Signature),
        Secp256r1(Secp256r1Signature),
        Passkey(PasskeyAuthenticator),
    );

    pub fn scheme(&self) -> SignatureScheme {
        match self {
            Self::Ed25519(_) => SignatureScheme::Ed25519,
            Self::Secp256k1(_) => SignatureScheme::Secp256k1,
            Self::Secp256r1(_) => SignatureScheme::Secp256r1,
            Self::Passkey(_) => SignatureScheme::PasskeyAuthenticator,
        }
    }
}

impl AsRef<[u8]> for MultisigMemberSignature {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Ed25519(s) => s.as_ref(),
            Self::Secp256k1(s) => s.as_ref(),
            Self::Secp256r1(s) => s.as_ref(),
            Self::Passkey(s) => s.signature.as_ref(),
        }
    }
}

impl TryFrom<UserSignature> for MultisigMemberSignature {
    type Error = MultisigError;

    fn try_from(signature: UserSignature) -> Result<Self, Self::Error> {
        match signature {
            UserSignature::Simple(simple) => Ok(simple.into()),
            UserSignature::Multisig(_) => Err(MultisigError::UnallowedSignatureType),
            UserSignature::ZkLoginAuthenticatorDeprecated => {
                Err(MultisigError::UnallowedSignatureType)
            }
            UserSignature::PasskeyAuthenticator(auth) => Ok(Self::Passkey(auth)),
            UserSignature::MoveAuthenticator(_) => Err(MultisigError::UnallowedSignatureType),
        }
    }
}

impl From<SimpleSignature> for MultisigMemberSignature {
    fn from(signature: SimpleSignature) -> Self {
        match signature {
            SimpleSignature::Ed25519 { signature, .. } => Self::Ed25519(signature),
            SimpleSignature::Secp256k1 { signature, .. } => Self::Secp256k1(signature),
            SimpleSignature::Secp256r1 { signature, .. } => Self::Secp256r1(signature),
        }
    }
}

#[cfg(feature = "proptest")]
impl proptest::arbitrary::Arbitrary for MultisigCommittee {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::{collection::vec, prelude::*};

        vec(
            (any::<PublicKey>(), 1u8..=WeightUnit::MAX),
            1..=MULTISIG_COMMITTEE_SIZE_MAX,
        )
        .prop_flat_map(|raw_members| {
            let mut members: Vec<MultisigMember> = Vec::with_capacity(raw_members.len());
            for (public_key, weight) in raw_members {
                if !members.iter().any(|m| m.public_key == public_key) {
                    members.push(MultisigMember { public_key, weight });
                }
            }
            let sum: ThresholdUnit = members.iter().map(|m| m.weight as ThresholdUnit).sum();
            (Just(members), 1..=sum)
        })
        .prop_map(|(members, threshold)| Self { members, threshold })
        .boxed()
    }
}

#[cfg(feature = "proptest")]
impl proptest::arbitrary::Arbitrary for MultisigAggregatedSignature {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::{collection::vec, prelude::*, sample::subsequence};

        any::<MultisigCommittee>()
            .prop_flat_map(|committee| {
                let n = committee.members.len();
                let all_indices: Vec<usize> = (0..n).collect();
                (Just(committee), subsequence(all_indices, 1..=n))
            })
            .prop_flat_map(|(committee, indices)| {
                let count = indices.len();
                let bitmap = indices
                    .iter()
                    .fold(0 as BitmapUnit, |acc, &i| acc | (1 << i));
                (
                    Just(committee),
                    Just(bitmap),
                    vec(any::<MultisigMemberSignature>(), count..=count),
                )
            })
            .prop_map(|(committee, bitmap, signatures)| Self {
                signatures,
                bitmap,
                committee,
                bytes: OnceLock::new(),
            })
            .boxed()
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization {
    use std::{
        borrow::Cow,
        hash::{Hash, Hasher},
        str::FromStr,
    };

    use base64ct::{Base64, Encoding};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::{Bytes, DeserializeAs};

    use super::*;
    use crate::{SignatureScheme, crypto::SignatureFromBytesError};

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
    #[serde(rename = "MultisigAggregatedSignature")]
    struct ReadableMultisigAggregatedSignature {
        signatures: Vec<MultisigMemberSignature>,
        bitmap: BitmapUnit,
        committee: MultisigCommittee,
    }

    #[derive(serde::Serialize)]
    #[serde(rename = "MultisigAggregatedSignature")]
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
                    bytes: OnceLock::new(),
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
            let (flag, tail) = bytes.split_first().ok_or(SignatureFromBytesError::new(
                "missing signature scheme flag",
            ))?;
            let scheme = SignatureScheme::from_byte(*flag).map_err(SignatureFromBytesError::new)?;

            if scheme != SignatureScheme::Multisig {
                return Err(SignatureFromBytesError::new("invalid multisig flag"));
            }

            if let Ok(multisig) = bcs::from_bytes::<Multisig>(tail) {
                let multisig = Self {
                    signatures: multisig.signatures,
                    bitmap: multisig.bitmap,
                    committee: multisig.committee,
                    bytes: OnceLock::new(),
                };
                multisig
                    .validate()
                    .map_err(|e| SignatureFromBytesError::new(format!("invalid multisig: {e}")))?;
                Ok(multisig)
            } else {
                Err(SignatureFromBytesError::new("invalid multisig"))
            }
        }
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    enum MemberSignature {
        Ed25519(Ed25519Signature),
        Secp256k1(Secp256k1Signature),
        Secp256r1(Secp256r1Signature),
        ZkLoginDeprecated,
        Passkey(PasskeyAuthenticator),
    }

    #[derive(serde::Deserialize, serde::Serialize)]
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
                    ReadableMemberSignature::ZkLoginDeprecated => {
                        return Err(serde::de::Error::custom(
                            "zkLoginDeprecated is not supported",
                        ));
                    }
                    ReadableMemberSignature::Passkey(authenticator) => Self::Passkey(authenticator),
                })
            } else {
                let binary = MemberSignature::deserialize(deserializer)?;
                Ok(match binary {
                    MemberSignature::Ed25519(signature) => Self::Ed25519(signature),
                    MemberSignature::Secp256k1(signature) => Self::Secp256k1(signature),
                    MemberSignature::Secp256r1(signature) => Self::Secp256r1(signature),
                    MemberSignature::ZkLoginDeprecated => {
                        return Err(serde::de::Error::custom(
                            "zkLoginDeprecated is not supported",
                        ));
                    }
                    MemberSignature::Passkey(authenticator) => Self::Passkey(authenticator),
                })
            }
        }
    }

    #[cfg(feature = "hash")]
    impl From<&MultisigCommittee> for crate::Address {
        fn from(committee: &MultisigCommittee) -> Self {
            committee.derive_address()
        }
    }

    /// This initialize the underlying bytes representation of
    /// [`MultisigAggregatedSignature`].
    /// It encodes [`MultisigAggregatedSignature`] as the MultiSig flag (0x03)
    /// concat with the bcs bytes of [`MultisigAggregatedSignature`] i.e. `flag
    /// || bcs_bytes(multiSig)`.
    impl AsRef<[u8]> for MultisigAggregatedSignature {
        fn as_ref(&self) -> &[u8] {
            self.bytes.get_or_init(|| self.to_bytes())
        }
    }

    impl Hash for MultisigAggregatedSignature {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.as_ref().hash(state);
        }
    }

    impl FromStr for MultisigAggregatedSignature {
        type Err = MultisigError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let bytes = Base64::decode_vec(s)?;
            let sig = MultisigAggregatedSignature::from_bytes(&bytes)?;

            Ok(sig)
        }
    }

    impl MultisigMemberSignature {
        pub fn to_base64(&self) -> String {
            let mut bytes: Vec<u8> = Vec::new();

            match self {
                MultisigMemberSignature::Ed25519(signature) => {
                    bytes.extend_from_slice(&[self.scheme() as u8]);
                    bytes.extend_from_slice(signature.as_ref());
                }
                MultisigMemberSignature::Secp256k1(signature) => {
                    bytes.extend_from_slice(&[self.scheme() as u8]);
                    bytes.extend_from_slice(signature.as_ref());
                }
                MultisigMemberSignature::Secp256r1(signature) => {
                    bytes.extend_from_slice(&[self.scheme() as u8]);
                    bytes.extend_from_slice(signature.as_ref());
                }
                MultisigMemberSignature::Passkey(authenticator) => {
                    bytes.extend_from_slice(&authenticator.to_bytes());
                }
            }

            Base64::encode_string(&bytes)
        }

        pub fn from_base64(s: &str) -> Result<Self, MultisigError> {
            let bytes = Base64::decode_vec(s)?;

            match bytes.first() {
                Some(x) => {
                    if x == &(SignatureScheme::Ed25519 as u8) {
                        let signature = Ed25519Signature::from_bytes(&bytes[1..])?;
                        Ok(Self::Ed25519(signature))
                    } else if x == &(SignatureScheme::Secp256k1 as u8) {
                        let signature = Secp256k1Signature::from_bytes(&bytes[1..])?;
                        Ok(Self::Secp256k1(signature))
                    } else if x == &(SignatureScheme::Secp256r1 as u8) {
                        let signature = Secp256r1Signature::from_bytes(&bytes[1..])?;
                        Ok(Self::Secp256r1(signature))
                    } else if x == &(SignatureScheme::PasskeyAuthenticator as u8) {
                        let signature = PasskeyAuthenticator::from_bytes(&bytes[..])?;
                        Ok(Self::Passkey(signature))
                    } else {
                        Err(MultisigError::UnallowedSignatureType)
                    }
                }
                _ => Err(MultisigError::InvalidInput),
            }
        }
    }

    impl FromStr for MultisigMemberSignature {
        type Err = MultisigError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Self::from_base64(s)
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
            vec![MultisigMember::new(PublicKey::Passkey(passkey_pk), 1)],
            1,
        )
        .unwrap();
        assert!(committee.validate().is_ok());

        let aggregated = MultisigAggregatedSignature::new_unchecked(
            vec![MultisigMemberSignature::Passkey(passkey_authenticator)],
            0b1,
            committee,
        );

        let bcs_bytes = bcs::to_bytes(&aggregated).unwrap();
        let from_bcs: MultisigAggregatedSignature = bcs::from_bytes(&bcs_bytes).unwrap();
        assert_eq!(aggregated, from_bcs);

        let json = serde_json::to_string(&aggregated).unwrap();
        let from_json: MultisigAggregatedSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(aggregated, from_json);
    }

    #[test]
    fn test_to_indices() {
        assert!(as_indices(0b11111111110).is_err());
        assert_eq!(as_indices(0b0000010110).unwrap(), vec![1, 2, 4]);
        assert_eq!(
            as_indices(0b1111111111).unwrap(),
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        );
    }

    /// `MultisigAggregatedSignature::new` must reject `UserSignature`s that
    /// are not provided in committee order, since the resulting bitmap and
    /// signatures vector would otherwise misalign at verification time.
    #[test]
    fn new_rejects_out_of_order_signatures() {
        use crate::{Ed25519PublicKey, Ed25519Signature, SimpleSignature};

        let pk0 = Ed25519PublicKey::new([1; 32]);
        let pk1 = Ed25519PublicKey::new([2; 32]);
        let pk2 = Ed25519PublicKey::new([3; 32]);

        let committee = MultisigCommittee::new(
            vec![
                MultisigMember::new(pk0, 1),
                MultisigMember::new(pk1, 1),
                MultisigMember::new(pk2, 1),
            ],
            2,
        )
        .unwrap();

        let dummy_sig = Ed25519Signature::new([0; 64]);
        let sig = |pk| {
            UserSignature::Simple(SimpleSignature::Ed25519 {
                signature: dummy_sig,
                public_key: pk,
            })
        };

        // In-order input is accepted and the bitmap matches the indices used.
        let ok =
            MultisigAggregatedSignature::new(vec![sig(pk0), sig(pk2)], committee.clone()).unwrap();
        assert_eq!(ok.bitmap(), 0b101);
        assert_eq!(ok.signatures().len(), 2);

        // Out-of-order input is rejected.
        let err = MultisigAggregatedSignature::new(vec![sig(pk2), sig(pk0)], committee.clone())
            .unwrap_err();
        assert!(
            matches!(err, MultisigError::SignaturesOutOfOrder),
            "expected SignaturesOutOfOrder, got {err:?}"
        );

        // Adjacent duplicates are reported as duplicates, not as ordering errors.
        let err =
            MultisigAggregatedSignature::new(vec![sig(pk0), sig(pk0)], committee).unwrap_err();
        assert!(
            matches!(err, MultisigError::DuplicatePublicKey),
            "expected DuplicatePublicKey, got {err:?}"
        );
    }

    #[test]
    fn member_signature_base64_roundtrip() {
        use crate::Ed25519Signature;

        let sig = MultisigMemberSignature::Ed25519(Ed25519Signature::new([0xAB; 64]));
        let encoded = sig.to_base64();
        let decoded = MultisigMemberSignature::from_base64(&encoded)
            .expect("from_base64 should accept what to_base64 produced");
        assert_eq!(
            sig, decoded,
            "to_base64/from_base64 must be inverses of each other"
        );
    }

    #[test]
    fn member_signature_base64_roundtrip_passkey() {
        let passkey_b64 = "BiVYDmenOnqS+thmz5m5SrZnWaKXZLVxgh+rri6LHXs25B0AAAAAnQF7InR5cGUiOiJ3ZWJhdXRobi5nZXQiLCAiY2hhbGxlbmdlIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTE3MyIsImNyb3NzT3JpZ2luIjpmYWxzZSwgInVua25vd24iOiAidW5rbm93biJ9YgJMwqcOmZI7F/N+K5SMe4DRYCb4/cDWW68SFneSHoD2GxKKhksbpZ5rZpdrjSYABTCsFQQBpLORzTvbj4edWKd/AsEBeovrGvHR9Ku7critg6k7qvfFlPUngujXfEzXd8Eg";
        let UserSignature::PasskeyAuthenticator(passkey_authenticator) =
            UserSignature::from_base64(passkey_b64).unwrap()
        else {
            panic!("expected passkey authenticator");
        };
        let sig = MultisigMemberSignature::Passkey(passkey_authenticator);
        let encoded = sig.to_base64();
        let decoded = MultisigMemberSignature::from_base64(&encoded)
            .expect("from_base64 should accept what to_base64 produced");
        assert_eq!(
            sig, decoded,
            "to_base64/from_base64 must be inverses of each other"
        );
    }

    #[test]
    fn validate_rejects_bitmap_bits_past_committee_size() {
        use crate::{Ed25519PublicKey, Ed25519Signature};

        let pk0 = Ed25519PublicKey::new([1; 32]);
        let pk1 = Ed25519PublicKey::new([2; 32]);
        let committee = MultisigCommittee::new(
            vec![MultisigMember::new(pk0, 1), MultisigMember::new(pk1, 1)],
            2,
        )
        .unwrap();

        let agg = MultisigAggregatedSignature::new_unchecked(
            vec![
                MultisigMemberSignature::Ed25519(Ed25519Signature::new([0; 64])),
                MultisigMemberSignature::Ed25519(Ed25519Signature::new([0; 64])),
            ],
            0b1100000000,
            committee,
        );

        let result = agg.validate();
        assert!(
            result.is_err(),
            "validate() must reject bitmap bits outside committee.members.len(), got Ok"
        );
    }

    #[test]
    fn new_rejects_duplicates() {
        use crate::{Ed25519PublicKey, Ed25519Signature, SimpleSignature};

        let pk0 = Ed25519PublicKey::new([1; 32]);
        let pk1 = Ed25519PublicKey::new([2; 32]);
        let pk2 = Ed25519PublicKey::new([3; 32]);

        let committee = MultisigCommittee::new(
            vec![
                MultisigMember::new(pk0, 1),
                MultisigMember::new(pk1, 1),
                MultisigMember::new(pk2, 1),
            ],
            2,
        )
        .unwrap();

        let dummy = Ed25519Signature::new([0; 64]);
        let sig = |pk| {
            UserSignature::Simple(SimpleSignature::Ed25519 {
                signature: dummy,
                public_key: pk,
            })
        };

        // pk0, pk0 — the same key appears twice in adjacent positions.
        let err = MultisigAggregatedSignature::new(vec![sig(pk0), sig(pk0)], committee.clone())
            .unwrap_err();
        assert!(
            matches!(err, MultisigError::DuplicatePublicKey),
            "adjacent duplicate should be reported as DuplicatePublicKey, got {err:?}"
        );

        // pk0, pk1, pk0 — pk0 reappears non-adjacently, which must also be
        // reported as a duplicate.
        let err = MultisigAggregatedSignature::new(vec![sig(pk0), sig(pk1), sig(pk0)], committee)
            .unwrap_err();
        assert!(
            matches!(err, MultisigError::DuplicatePublicKey),
            "non-adjacent duplicate should be reported as DuplicatePublicKey, got {err:?}"
        );
    }
}
