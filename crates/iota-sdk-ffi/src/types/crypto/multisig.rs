// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_sdk::types::SignatureScheme;

use crate::{
    error::Result,
    types::{
        address::Address,
        crypto::{
            Ed25519PublicKey, Ed25519Signature, Secp256k1PublicKey, Secp256k1Signature,
            Secp256r1PublicKey, Secp256r1Signature,
            passkey::{PasskeyAuthenticator, PasskeyPublicKey},
        },
    },
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
///                             zklogin-multisig-member-signature-deprecated /
///                             passkey-multisig-member-signature
///
/// ed25519-multisig-member-signature               = %d00 ed25519-signature
/// secp256k1-multisig-member-signature             = %d01 secp256k1-signature
/// secp256r1-multisig-member-signature             = %d02 secp256r1-signature
/// zklogin-multisig-member-signature-deprecated    = %d03
/// passkey-multisig-member-signature               = %d04 passkey-authenticator
/// ```
#[derive(Debug, PartialEq, Eq, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct MultisigMemberSignature(pub iota_sdk::types::MultisigMemberSignature);

#[uniffi::export]
impl MultisigMemberSignature {
    pub fn is_ed25519(&self) -> bool {
        self.0.is_ed25519()
    }

    pub fn as_ed25519_opt(&self) -> Option<Arc<Ed25519Signature>> {
        self.0
            .as_ed25519_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn as_ed25519(&self) -> Ed25519Signature {
        (*self.0.as_ed25519()).into()
    }

    pub fn is_secp256k1(&self) -> bool {
        self.0.is_secp256k1()
    }

    pub fn as_secp256k1_opt(&self) -> Option<Arc<Secp256k1Signature>> {
        self.0
            .as_secp256k1_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn as_secp256k1(&self) -> Secp256k1Signature {
        (*self.0.as_secp256k1()).into()
    }

    pub fn is_secp256r1(&self) -> bool {
        self.0.is_secp256r1()
    }

    pub fn as_secp256r1_opt(&self) -> Option<Arc<Secp256r1Signature>> {
        self.0
            .as_secp256r1_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn as_secp256r1(&self) -> Secp256r1Signature {
        (*self.0.as_secp256r1()).into()
    }

    pub fn is_passkey(&self) -> bool {
        self.0.is_passkey()
    }

    pub fn as_passkey_opt(&self) -> Option<Arc<PasskeyAuthenticator>> {
        self.0
            .as_passkey_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn as_passkey(&self) -> PasskeyAuthenticator {
        self.0.as_passkey().clone().into()
    }
}

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
#[derive(Debug, PartialEq, Eq, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct PublicKey(pub iota_sdk::types::PublicKey);

#[uniffi::export]
impl PublicKey {
    pub fn is_ed25519(&self) -> bool {
        self.0.is_ed25519()
    }

    pub fn as_ed25519_opt(&self) -> Option<Arc<Ed25519PublicKey>> {
        self.0
            .as_ed25519_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn as_ed25519(&self) -> Ed25519PublicKey {
        (*self.0.as_ed25519()).into()
    }

    pub fn is_secp256k1(&self) -> bool {
        self.0.is_secp256k1()
    }

    pub fn as_secp256k1_opt(&self) -> Option<Arc<Secp256k1PublicKey>> {
        self.0
            .as_secp256k1_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn as_secp256k1(&self) -> Secp256k1PublicKey {
        (*self.0.as_secp256k1()).into()
    }

    pub fn is_secp256r1(&self) -> bool {
        self.0.is_secp256r1()
    }

    pub fn as_secp256r1_opt(&self) -> Option<Arc<Secp256r1PublicKey>> {
        self.0
            .as_secp256r1_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn as_secp256r1(&self) -> Secp256r1PublicKey {
        (*self.0.as_secp256r1()).into()
    }

    pub fn is_passkey(&self) -> bool {
        self.0.is_passkey()
    }

    pub fn as_passkey_opt(&self) -> Option<Arc<PasskeyPublicKey>> {
        self.0
            .as_passkey_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn as_passkey(&self) -> PasskeyPublicKey {
        self.0.as_passkey().clone().into()
    }

    pub fn scheme(&self) -> SignatureScheme {
        self.0.scheme()
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
/// See <https://github.com/RoaringBitmap/RoaringFormatSpec> for the specification for the
/// serialized format of RoaringBitmaps.
#[derive(Debug, PartialEq, Eq, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct MultisigAggregatedSignature(pub iota_sdk::types::MultisigAggregatedSignature);

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
    pub fn insecure_new(
        signatures: Vec<Arc<MultisigMemberSignature>>,
        bitmap: u16,
        committee: &MultisigCommittee,
    ) -> Self {
        Self(iota_sdk::types::MultisigAggregatedSignature::insecure_new(
            signatures.into_iter().map(|s| s.0.clone()).collect(),
            bitmap,
            committee.0.clone(),
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
#[derive(Debug, PartialEq, Eq, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct MultisigCommittee(pub iota_sdk::types::MultisigCommittee);

#[uniffi::export]
impl MultisigCommittee {
    /// Construct a new committee from a list of `MultisigMember`s and a
    /// `threshold`.
    ///
    /// Note that the order of the members is significant towards deriving the
    /// `Address` governed by this committee.
    #[uniffi::constructor]
    pub fn new(members: Vec<Arc<MultisigMember>>, threshold: u16) -> Self {
        // TODO
        Self(iota_sdk::types::MultisigCommittee::insecure_new(
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
    pub fn is_valid(&self) -> Result<()> {
        Ok(self.0.is_valid()?)
    }

    /// Derive an `Address` from this MultisigCommittee.
    ///
    /// A MultiSig address
    /// is defined as the 32-byte Blake2b hash of serializing the
    /// `SignatureScheme` flag (0x03), the threshold (in little endian), and
    /// the concatenation of all n flag, public keys and its weight.
    ///
    /// `hash(0x03 || threshold || flag_1 || pk_1 || weight_1
    /// || ... || flag_n || pk_n || weight_n)`.
    pub fn derive_address(&self) -> Address {
        self.0.derive_address().into()
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
#[derive(Debug, PartialEq, Eq, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct MultisigMember(pub iota_sdk::types::MultisigMember);

#[uniffi::export]
impl MultisigMember {
    /// Construct a new member from a `PublicKey` and a `weight`.
    #[uniffi::constructor]
    pub fn new(public_key: &PublicKey, weight: u8) -> Self {
        Self(iota_sdk::types::MultisigMember::new(
            public_key.0.clone(),
            weight,
        ))
    }

    /// This member's public key.
    pub fn public_key(&self) -> PublicKey {
        self.0.public_key().clone().into()
    }

    /// Weight of this member's signature.
    pub fn weight(&self) -> u8 {
        self.0.weight()
    }
}

crate::export_iota_types_objects_bcs_conversion!(
    MultisigMemberSignature,
    PublicKey,
    MultisigAggregatedSignature,
    MultisigCommittee,
    MultisigMember
);
crate::export_iota_types_objects_json_conversion!(
    MultisigMemberSignature,
    PublicKey,
    MultisigAggregatedSignature,
    MultisigCommittee,
    MultisigMember
);
