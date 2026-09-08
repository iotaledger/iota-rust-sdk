// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

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
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct MultisigMember {
    public_key: PublicKey,
    #[cfg_attr(feature = "bcs-schema", bcs_schema(as_type = "u8"))]
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

impl crate::TreeDisplay for MultisigMember {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Multisig Member")?;
        w.leaf("Public Key", &self.public_key, false)?;
        w.leaf("Weight", &self.weight, true)
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
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
pub struct MultisigCommittee {
    /// A list of committee members and their corresponding weight.
    members: Vec<MultisigMember>,
    /// If the total weight of the public keys corresponding to verified
    /// signatures is larger than threshold, the Multisig is verified.
    #[cfg_attr(feature = "bcs-schema", bcs_schema(as_type = "u16"))]
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
    pub fn index(&self, public_key: &PublicKey) -> Option<u8> {
        self.members
            .iter()
            .position(|member| &member.public_key == public_key)
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

impl crate::TreeDisplay for MultisigCommittee {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Multisig Committee")?;
        w.children("Members", &self.members, false)?;
        w.leaf("Threshold", &self.threshold, true)
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
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
pub struct MultisigAggregatedSignature {
    /// The plain signature encoded with signature scheme.
    ///
    /// The signatures must be in the same order as they are listed in the
    /// committee.
    signatures: Vec<MultisigMemberSignature>,
    /// A bitmap that indicates the position of which public key the signature
    /// should be authenticated with.
    #[cfg_attr(feature = "bcs-schema", bcs_schema(as_type = "u16"))]
    bitmap: BitmapUnit,
    /// The public key encoded with each public key with its signature scheme
    /// used along with the corresponding weight.
    committee: MultisigCommittee,
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
                .index(&pk)
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

impl crate::TreeDisplay for MultisigAggregatedSignature {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Multisig Aggregated Signature")?;
        w.child("Committee", &self.committee, false)?;
        w.children("Signatures", &self.signatures, false)?;
        w.leaf("Bitmap", &self.bitmap, true)
    }
}

crate::impl_tree_display!(
    MultisigMember,
    MultisigCommittee,
    MultisigAggregatedSignature,
    MultisigMemberSignature
);

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
#[derive(Clone, Debug, derive_more::From, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[non_exhaustive]
pub enum MultisigMemberSignature {
    Ed25519(Ed25519Signature),
    Secp256k1(Secp256k1Signature),
    Secp256r1(Secp256r1Signature),
    Passkey(PasskeyAuthenticator),
}

impl crate::TreeDisplay for MultisigMemberSignature {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.enum_name("Multisig Member Signature");
        match self {
            Self::Ed25519(v) => w.header(&format!("Ed25519Signature({v})")),
            Self::Secp256k1(v) => w.header(&format!("Secp256k1Signature({v})")),
            Self::Secp256r1(v) => w.header(&format!("Secp256r1Signature({v})")),
            Self::Passkey(v) => v.fmt_tree(w),
        }
    }
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
            })
            .boxed()
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
pub(crate) mod serialization {
    use std::{borrow::Cow, str::FromStr};

    use base64ct::{Base64, Encoding};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::{Bytes, DeserializeAs};

    use super::*;
    use crate::{SignatureScheme, crypto::SignatureFromBytesError};

    /// Owned wire shape of an aggregated multisig: the flat
    /// `signatures || bitmap || committee` body without the scheme flag or
    /// length prefix. `UserSignatureBody::Multisig` embeds this type directly
    /// (the enum tag supplies the flag and the outer `UserSignature` the
    /// length prefix), while `MultisigAggregatedSignature`'s own serde keeps
    /// the historical `bytes`-wrapped `flag || body` form.
    #[derive(serde::Deserialize)]
    pub(crate) struct Multisig {
        signatures: Vec<MultisigMemberSignature>,
        bitmap: BitmapUnit,
        committee: MultisigCommittee,
    }

    #[derive(serde::Serialize)]
    struct MultisigRef<'a> {
        signatures: &'a [MultisigMemberSignature],
        bitmap: BitmapUnit,
        committee: &'a MultisigCommittee,
    }

    impl TryFrom<Multisig> for MultisigAggregatedSignature {
        type Error = SignatureFromBytesError;

        fn try_from(multisig: Multisig) -> Result<Self, Self::Error> {
            let multisig = Self {
                signatures: multisig.signatures,
                bitmap: multisig.bitmap,
                committee: multisig.committee,
            };
            multisig
                .validate()
                .map_err(|e| SignatureFromBytesError::new(format!("invalid multisig: {e}")))?;
            Ok(multisig)
        }
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
                })
            } else {
                let bytes: Cow<'de, [u8]> = Bytes::deserialize_as(deserializer)?;
                Self::from_bytes(bytes).map_err(serde::de::Error::custom)
            }
        }
    }

    impl MultisigAggregatedSignature {
        /// Encode this aggregated signature as `flag || bcs-body`, where
        /// `flag` is the multisig scheme byte (`0x03`).
        pub fn to_bytes(&self) -> Vec<u8> {
            let mut buf = vec![SignatureScheme::Multisig as u8];
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

            bcs::from_bytes::<Multisig>(tail)
                .map_err(|_| SignatureFromBytesError::new("invalid multisig"))?
                .try_into()
        }
    }

    /// Wire shape for `MultisigMemberSignature`.
    ///
    /// The `ZkLoginDeprecated` placeholder pins `Passkey` at flag `%d04`; it
    /// is rejected on deserialization. The passkey arm serializes through
    /// `PasskeyAuthenticator`'s own serde, i.e. as length-prefixed `bytes`
    /// containing `passkey-flag || passkey-authenticator`.
    #[derive(serde::Deserialize, serde::Serialize)]
    #[cfg_attr(
        feature = "bcs-schema",
        derive(iota_bcs_schema::BcsSchema),
        bcs_schema(name = "multisig-member-signature")
    )]
    enum MemberSignature {
        Ed25519(Ed25519Signature),
        Secp256k1(Secp256k1Signature),
        Secp256r1(Secp256r1Signature),
        #[cfg_attr(feature = "bcs-schema", bcs_schema(skip))]
        ZkLoginDeprecated,
        Passkey(
            #[cfg_attr(feature = "bcs-schema", bcs_schema(as_type = "bytes"))] PasskeyAuthenticator,
        ),
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

    /// A standalone `MultisigAggregatedSignature` BCS-serializes as
    /// length-prefixed bytes containing `multisig-flag || body`, exactly the
    /// `to_bytes` form. A round-trip test cannot detect losing (or doubling)
    /// that framing, so it is pinned here byte-by-byte.
    #[test]
    fn multisig_standalone_bcs_framing() {
        use base64ct::{Base64, Encoding};

        // A multisig `UserSignature` from a mainnet transaction, in the flat
        // `[0x03 flag][body]` wire form (the `to_bytes` / explorer encoding):
        // https://explorer.iota.org/txblock/BUPSmkG8QZgr1NtVNjFaJMYsArkaWMECs7RHbEZRZUEU?network=https%3A%2F%2Findexer.mainnet.iota.cafe
        let multisig_b64 = "AwIA+zI2waYMirpLgCXsqGcuy+VPNToMkxYeBxkQVSgFdIS/TnAHQKs9FFAzHTfV2iSJuO25oIw5dnu9KEBSZwiqBQAf+R79IrKzolrY7mAM6TmE8T9sKk496ztesq0ao6a5BDFeH0QrIXJ68PZFAdEE86k3wh1WkeIYjxAMrIBpy9YBGAAFALurCXoe8wunaE2g6O2CtIZW4lSIf/fImJrdqRvZtlphAQCpMi2gCtRO9jNLl3bwc1x8IB/YYs1P6XpUEQbwzh2lGAEABYLKuo/1LUczMu80FayRheNYXavDC8l+QLX/s4S9i7QBAJYYQ5QWs/aT8+VwA+Vh3wswa90eqAaf6N4yzYUSXuTCAQBR6+eXlJ4GViO9z7QXRPSUaRPR9DlyDjc6S9lz61JNLgECAA==";
        let flag_and_body = Base64::decode_vec(multisig_b64).unwrap();
        let UserSignature::Multisig(sig) = UserSignature::from_bytes(&flag_and_body).unwrap()
        else {
            panic!("expected multisig signature");
        };

        // `to_bytes` is the flat `flag || body`; the standalone BCS form wraps
        // that same blob in a ULEB length prefix (identical to BCS-encoding the
        // bytes themselves).
        assert_eq!(
            sig.to_bytes(),
            flag_and_body,
            "multisig `to_bytes` must be the flat `flag || body` wire form"
        );
        assert_eq!(
            bcs::to_bytes(&sig).unwrap(),
            bcs::to_bytes(&flag_and_body).unwrap(),
            "standalone BCS must be the ULEB-length-prefixed `flag || body` wire form"
        );
        let decoded: MultisigAggregatedSignature =
            bcs::from_bytes(&bcs::to_bytes(&sig).unwrap()).unwrap();
        assert_eq!(sig, decoded);
    }

    /// A passkey member signature is BCS-framed as `%d04` followed by
    /// length-prefixed bytes containing `passkey-flag || passkey body` — the
    /// historical wrapping produced by `PasskeyAuthenticator`'s serde. A
    /// round-trip test cannot detect losing (or doubling) that framing, so it
    /// is pinned here byte-by-byte.
    #[test]
    fn member_signature_passkey_bcs_framing() {
        use base64ct::{Base64, Encoding};

        let passkey_b64 = "BiVYDmenOnqS+thmz5m5SrZnWaKXZLVxgh+rri6LHXs25B0AAAAAnQF7InR5cGUiOiJ3ZWJhdXRobi5nZXQiLCAiY2hhbGxlbmdlIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTE3MyIsImNyb3NzT3JpZ2luIjpmYWxzZSwgInVua25vd24iOiAidW5rbm93biJ9YgJMwqcOmZI7F/N+K5SMe4DRYCb4/cDWW68SFneSHoD2GxKKhksbpZ5rZpdrjSYABTCsFQQBpLORzTvbj4edWKd/AsEBeovrGvHR9Ku7critg6k7qvfFlPUngujXfEzXd8Eg";
        let passkey_wire = Base64::decode_vec(passkey_b64).unwrap();
        let UserSignature::PasskeyAuthenticator(passkey_authenticator) =
            UserSignature::from_base64(passkey_b64).unwrap()
        else {
            panic!("expected passkey authenticator");
        };

        let bytes =
            bcs::to_bytes(&MultisigMemberSignature::Passkey(passkey_authenticator)).unwrap();
        // `%d04` member tag, then the passkey as length-prefixed bytes whose
        // contents are exactly the standalone `flag || body` wire form.
        assert_eq!(bytes[0], 0x04, "passkey member signature must use tag 4");
        let expected = bcs::to_bytes(&passkey_wire).unwrap();
        assert_eq!(
            bytes[1..],
            expected[..],
            "passkey member payload must be the length-prefixed standalone wire form"
        );
    }

    /// The BCS tag of a multisig `MemberSignature` is the on-chain wire
    /// format, so the variant indices must stay fixed. A round-trip test
    /// can't catch a shift (encode and decode move together), so the tag
    /// values are pinned here against hardcoded expectations. In particular
    /// this guards the `ZkLoginDeprecated` placeholder kept at index `0x03`:
    /// removing it would silently shift `Passkey` from `0x04` to `0x03`.
    #[test]
    fn member_signature_bcs_tags() {
        use crate::Ed25519Signature;

        let ed25519 = MultisigMemberSignature::Ed25519(Ed25519Signature::new([0xAB; 64]));
        assert_eq!(
            bcs::to_bytes(&ed25519).unwrap()[0],
            0x00,
            "ed25519 member must use BCS tag 0x00"
        );

        let passkey_b64 = "BiVYDmenOnqS+thmz5m5SrZnWaKXZLVxgh+rri6LHXs25B0AAAAAnQF7InR5cGUiOiJ3ZWJhdXRobi5nZXQiLCAiY2hhbGxlbmdlIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTE3MyIsImNyb3NzT3JpZ2luIjpmYWxzZSwgInVua25vd24iOiAidW5rbm93biJ9YgJMwqcOmZI7F/N+K5SMe4DRYCb4/cDWW68SFneSHoD2GxKKhksbpZ5rZpdrjSYABTCsFQQBpLORzTvbj4edWKd/AsEBeovrGvHR9Ku7critg6k7qvfFlPUngujXfEzXd8Eg";
        let UserSignature::PasskeyAuthenticator(passkey_authenticator) =
            UserSignature::from_base64(passkey_b64).unwrap()
        else {
            panic!("expected passkey authenticator");
        };
        let passkey = MultisigMemberSignature::Passkey(passkey_authenticator);
        assert_eq!(
            bcs::to_bytes(&passkey).unwrap()[0],
            0x04,
            "passkey member must use BCS tag 0x04"
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

    /// Pin the committee validation rules enforced by
    /// [`MultisigCommittee::new`].
    #[test]
    fn committee_new_validation() {
        use crate::Ed25519PublicKey;

        let member = |b: u8| MultisigMember::new(Ed25519PublicKey::new([b; 32]), 1);

        // A well-formed committee is accepted.
        assert!(MultisigCommittee::new(vec![member(1), member(2)], 2).is_ok());

        // Zero threshold.
        assert!(matches!(
            MultisigCommittee::new(vec![member(1)], 0),
            Err(MultisigError::ZeroThreshold)
        ));

        // Empty committee.
        assert!(matches!(
            MultisigCommittee::new(vec![], 1),
            Err(MultisigError::EmptyCommittee)
        ));

        // Zero-weight member.
        assert!(matches!(
            MultisigCommittee::new(
                vec![MultisigMember::new(Ed25519PublicKey::new([1; 32]), 0)],
                1
            ),
            Err(MultisigError::ZeroWeightMember)
        ));

        // Threshold larger than the total weight.
        assert!(matches!(
            MultisigCommittee::new(vec![member(1), member(2)], 3),
            Err(MultisigError::InsufficientWeight(2, 3))
        ));

        // Duplicate public keys.
        assert!(matches!(
            MultisigCommittee::new(vec![member(1), member(1)], 1),
            Err(MultisigError::DuplicatePublicKey)
        ));

        // More than `MULTISIG_COMMITTEE_SIZE_MAX` members.
        let too_many = (0..=MULTISIG_COMMITTEE_SIZE_MAX as u8)
            .map(member)
            .collect();
        assert!(matches!(
            MultisigCommittee::new(too_many, 1),
            Err(MultisigError::CommitteeTooLarge(n)) if n == MULTISIG_COMMITTEE_SIZE_MAX + 1
        ));
    }

    /// Pin the multisig address derivation against accidental changes. A
    /// committee with a fixed set of public keys and weights must always map
    /// to the same address.
    #[cfg(feature = "hash")]
    #[test]
    fn derive_address_is_stable() {
        use crate::{Address, Ed25519PublicKey, Secp256k1PublicKey, Secp256r1PublicKey};

        let committee = MultisigCommittee::new(
            vec![
                MultisigMember::new(Ed25519PublicKey::new([1; 32]), 1),
                MultisigMember::new(Secp256k1PublicKey::new([2; 33]), 2),
                MultisigMember::new(Secp256r1PublicKey::new([3; 33]), 3),
            ],
            2,
        )
        .unwrap();

        assert_eq!(
            committee.derive_address(),
            Address::from_hex("0x391d9897d470cda2a489f59b54a04f2d8fa7bcb9c1ac978872689b477909cffe")
                .unwrap()
        );
    }

    /// `new` rejects empty signature lists and lists longer than the committee.
    #[test]
    fn new_rejects_invalid_signature_count() {
        use crate::{Ed25519PublicKey, Ed25519Signature, SimpleSignature};

        let committee = MultisigCommittee::new(
            vec![
                MultisigMember::new(Ed25519PublicKey::new([1; 32]), 1),
                MultisigMember::new(Ed25519PublicKey::new([2; 32]), 1),
            ],
            2,
        )
        .unwrap();

        let dummy = Ed25519Signature::new([0; 64]);
        let sig = |b: u8| {
            UserSignature::Simple(SimpleSignature::Ed25519 {
                signature: dummy,
                public_key: Ed25519PublicKey::new([b; 32]),
            })
        };

        // Empty signature list.
        assert!(matches!(
            MultisigAggregatedSignature::new(vec![], committee.clone()),
            Err(MultisigError::InvalidSignatureNumber)
        ));

        // More signatures than committee members.
        assert!(matches!(
            MultisigAggregatedSignature::new(vec![sig(1), sig(2), sig(3)], committee),
            Err(MultisigError::InvalidSignatureNumber)
        ));
    }

    /// The getters expose the committee, member signatures, bitmap, and the
    /// indices derived from the bitmap.
    #[test]
    fn aggregated_signature_getters() {
        use crate::{Ed25519PublicKey, Ed25519Signature, SimpleSignature};

        let pk0 = Ed25519PublicKey::new([1; 32]);
        let pk1 = Ed25519PublicKey::new([2; 32]);
        let committee = MultisigCommittee::new(
            vec![MultisigMember::new(pk0, 1), MultisigMember::new(pk1, 1)],
            2,
        )
        .unwrap();

        let dummy = Ed25519Signature::new([7; 64]);
        let sig = |pk| {
            UserSignature::Simple(SimpleSignature::Ed25519 {
                signature: dummy,
                public_key: pk,
            })
        };
        let aggregated =
            MultisigAggregatedSignature::new(vec![sig(pk0), sig(pk1)], committee.clone()).unwrap();

        assert_eq!(aggregated.committee(), &committee);
        assert_eq!(aggregated.bitmap(), 0b11);
        assert_eq!(aggregated.signatures().len(), 2);
        assert_eq!(aggregated.indices().unwrap(), vec![0, 1]);
    }
}
