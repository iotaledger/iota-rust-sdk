// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_types::SignatureScheme;

use crate::types::crypto::{
    Ed25519PublicKey, Ed25519Signature, Secp256k1PublicKey, Secp256k1Signature, Secp256r1PublicKey,
    Secp256r1Signature,
    zklogin::{ZkLoginAuthenticator, ZkLoginPublicIdentifier},
};

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
#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct MultisigMemberSignature(pub iota_types::MultisigMemberSignature);

#[uniffi::export]
impl MultisigMemberSignature {
    pub fn is_ed25519(&self) -> bool {
        matches!(self.0, iota_types::MultisigMemberSignature::Ed25519(_))
    }

    pub fn as_ed25519_opt(&self) -> Option<Arc<Ed25519Signature>> {
        if let iota_types::MultisigMemberSignature::Ed25519(sig) = self.0.clone() {
            Some(Arc::new(sig.into()))
        } else {
            None
        }
    }

    pub fn as_ed25519(&self) -> Arc<Ed25519Signature> {
        self.as_ed25519_opt().expect("not a ed25519 signature")
    }

    pub fn is_secp256k1(&self) -> bool {
        matches!(self.0, iota_types::MultisigMemberSignature::Secp256k1(_))
    }

    pub fn as_secp256k1_opt(&self) -> Option<Arc<Secp256k1Signature>> {
        if let iota_types::MultisigMemberSignature::Secp256k1(sig) = self.0.clone() {
            Some(Arc::new(sig.into()))
        } else {
            None
        }
    }

    pub fn as_secp256k1(&self) -> Arc<Secp256k1Signature> {
        self.as_secp256k1_opt().expect("not a secp256k1 signature")
    }

    pub fn is_secp256r1(&self) -> bool {
        matches!(self.0, iota_types::MultisigMemberSignature::Secp256r1(_))
    }

    pub fn as_secp256r1_opt(&self) -> Option<Arc<Secp256r1Signature>> {
        if let iota_types::MultisigMemberSignature::Secp256r1(sig) = self.0.clone() {
            Some(Arc::new(sig.into()))
        } else {
            None
        }
    }

    pub fn as_secp256r1(&self) -> Arc<Secp256r1Signature> {
        self.as_secp256r1_opt().expect("not a secp256r1 signature")
    }

    pub fn is_zklogin(&self) -> bool {
        matches!(self.0, iota_types::MultisigMemberSignature::ZkLogin(_))
    }

    pub fn as_zklogin_opt(&self) -> Option<Arc<ZkLoginAuthenticator>> {
        if let iota_types::MultisigMemberSignature::ZkLogin(sig) = self.0.clone() {
            Some(Arc::new((*sig).into()))
        } else {
            None
        }
    }

    pub fn as_zklogin(&self) -> Arc<ZkLoginAuthenticator> {
        self.as_zklogin_opt().expect("not a zklogin authenticator")
    }
}

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct MultisigMemberPublicKey(pub iota_types::MultisigMemberPublicKey);

#[uniffi::export]
impl MultisigMemberPublicKey {
    pub fn is_ed25519(&self) -> bool {
        matches!(self.0, iota_types::MultisigMemberPublicKey::Ed25519(_))
    }

    pub fn as_ed25519_opt(&self) -> Option<Arc<Ed25519PublicKey>> {
        if let iota_types::MultisigMemberPublicKey::Ed25519(key) = self.0.clone() {
            Some(Arc::new(key.into()))
        } else {
            None
        }
    }

    pub fn as_ed25519(&self) -> Arc<Ed25519PublicKey> {
        self.as_ed25519_opt().expect("not a ed25519 public key")
    }

    pub fn is_secp256k1(&self) -> bool {
        matches!(self.0, iota_types::MultisigMemberPublicKey::Secp256k1(_))
    }

    pub fn as_secp256k1_opt(&self) -> Option<Arc<Secp256k1PublicKey>> {
        if let iota_types::MultisigMemberPublicKey::Secp256k1(key) = self.0.clone() {
            Some(Arc::new(key.into()))
        } else {
            None
        }
    }

    pub fn as_secp256k1(&self) -> Arc<Secp256k1PublicKey> {
        self.as_secp256k1_opt().expect("not a secp256k1 public key")
    }

    pub fn is_secp256r1(&self) -> bool {
        matches!(self.0, iota_types::MultisigMemberPublicKey::Secp256r1(_))
    }

    pub fn as_secp256r1_opt(&self) -> Option<Arc<Secp256r1PublicKey>> {
        if let iota_types::MultisigMemberPublicKey::Secp256r1(key) = self.0.clone() {
            Some(Arc::new(key.into()))
        } else {
            None
        }
    }

    pub fn as_secp256r1(&self) -> Arc<Secp256r1PublicKey> {
        self.as_secp256r1_opt().expect("not a secp256r1 public key")
    }

    pub fn is_zklogin(&self) -> bool {
        matches!(self.0, iota_types::MultisigMemberPublicKey::ZkLogin(_))
    }

    pub fn as_zklogin_opt(&self) -> Option<Arc<ZkLoginPublicIdentifier>> {
        if let iota_types::MultisigMemberPublicKey::ZkLogin(key) = self.0.clone() {
            Some(Arc::new(key.into()))
        } else {
            None
        }
    }

    pub fn as_zklogin(&self) -> Arc<ZkLoginPublicIdentifier> {
        self.as_zklogin_opt().expect("not a zklogin authenticator")
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
#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct MultisigAggregatedSignature(pub iota_types::MultisigAggregatedSignature);

#[uniffi::export]
impl MultisigAggregatedSignature {
    /// Construct a new aggregated multisig signature.
    ///
    /// Since the list of signatures doesn't contain sufficient information to
    /// identify which committee member provided the signature, it is up to
    /// the caller to ensure that the provided signature list is in the same
    /// order as it's corresponding member in the provided committee
    /// and that it's position in the provided bitmap is set.
    #[uniffi::constructor]
    pub fn new(
        committee: &MultisigCommittee,
        signatures: Vec<Arc<MultisigMemberSignature>>,
        bitmap: u16,
    ) -> Self {
        Self(iota_types::MultisigAggregatedSignature::new(
            committee.0.clone(),
            signatures.into_iter().map(|s| s.0.clone()).collect(),
            bitmap,
        ))
    }

    /// The list of signatures from committee members
    pub fn signatures(&self) -> Vec<Arc<MultisigMemberSignature>> {
        self.0
            .signatures()
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }

    /// The bitmap that indicates which committee members provided their
    /// signature.
    pub fn bitmap(&self) -> u16 {
        self.0.bitmap()
    }

    pub fn committee(&self) -> MultisigCommittee {
        self.0.committee().clone().into()
    }
}

/// A multisig committee
///
/// A `MultisigCommittee` is a set of members who collectively control a single
/// `Address` on the IOTA blockchain. The number of required signautres to
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
#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct MultisigCommittee(pub iota_types::MultisigCommittee);

#[uniffi::export]
impl MultisigCommittee {
    /// Construct a new committee from a list of `MultisigMember`s and a
    /// `threshold`.
    ///
    /// Note that the order of the members is significant towards deriving the
    /// `Address` governed by this committee.
    #[uniffi::constructor]
    pub fn new(members: Vec<Arc<MultisigMember>>, threshold: u16) -> Self {
        Self(iota_types::MultisigCommittee::new(
            members.into_iter().map(|m| m.0.clone()).collect(),
            threshold,
        ))
    }

    /// The members of the committee
    pub fn members(&self) -> Vec<Arc<MultisigMember>> {
        self.0
            .members()
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }

    /// The total signature weight required to authorize a transaction for the
    /// address corresponding to this `MultisigCommittee`.
    pub fn threshold(&self) -> u16 {
        self.0.threshold()
    }

    /// Return the flag for this signature scheme
    pub fn scheme(&self) -> SignatureScheme {
        self.0.scheme()
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
        self.0.is_valid()
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
#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct MultisigMember(pub iota_types::MultisigMember);

#[uniffi::export]
impl MultisigMember {
    /// Construct a new member from a `MultisigMemberPublicKey` and a `weight`.
    #[uniffi::constructor]
    pub fn new(public_key: &MultisigMemberPublicKey, weight: u8) -> Self {
        Self(iota_types::MultisigMember::new(
            public_key.0.clone(),
            weight,
        ))
    }

    /// This member's public key.
    pub fn public_key(&self) -> MultisigMemberPublicKey {
        self.0.public_key().clone().into()
    }

    /// Weight of this member's signature.
    pub fn weight(&self) -> u8 {
        self.0.weight()
    }
}
