// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::{
    MultisigAggregatedSignature, MultisigCommittee, MultisigMemberPublicKey,
    MultisigMemberSignature, UserSignature,
};

use crate::{SignatureError, Verifier};

#[derive(Default, Debug, Clone, PartialEq)]
pub struct MultisigVerifier {
    #[cfg(feature = "zklogin")]
    zklogin_verifier: Option<crate::zklogin::ZkloginVerifier>,
}

impl MultisigVerifier {
    pub fn new() -> Self {
        Default::default()
    }

    fn verify_member_signature(
        &self,
        message: &[u8],
        member_public_key: &MultisigMemberPublicKey,
        signature: &MultisigMemberSignature,
    ) -> Result<(), SignatureError> {
        match (member_public_key, signature) {
            #[cfg(not(feature = "ed25519"))]
            (MultisigMemberPublicKey::Ed25519(_), MultisigMemberSignature::Ed25519(_)) => Err(
                SignatureError::from_source("support for ed25519 is not enabled"),
            ),
            #[cfg(feature = "ed25519")]
            (
                MultisigMemberPublicKey::Ed25519(ed25519_public_key),
                MultisigMemberSignature::Ed25519(ed25519_signature),
            ) => crate::ed25519::Ed25519VerifyingKey::new(ed25519_public_key)?
                .verify(message, ed25519_signature),
            #[cfg(not(feature = "secp256k1"))]
            (MultisigMemberPublicKey::Secp256k1(_), MultisigMemberSignature::Secp256k1(_)) => Err(
                SignatureError::from_source("support for secp256k1 is not enabled"),
            ),
            #[cfg(feature = "secp256k1")]
            (
                MultisigMemberPublicKey::Secp256k1(k1_public_key),
                MultisigMemberSignature::Secp256k1(k1_signature),
            ) => crate::secp256k1::Secp256k1VerifyingKey::new(k1_public_key)?
                .verify(message, k1_signature),
            #[cfg(not(feature = "secp256r1"))]
            (MultisigMemberPublicKey::Secp256r1(_), MultisigMemberSignature::Secp256r1(_)) => Err(
                SignatureError::from_source("support for secp256r1 is not enabled"),
            ),
            #[cfg(feature = "secp256r1")]
            (
                MultisigMemberPublicKey::Secp256r1(r1_public_key),
                MultisigMemberSignature::Secp256r1(r1_signature),
            ) => crate::secp256r1::Secp256r1VerifyingKey::new(r1_public_key)?
                .verify(message, r1_signature),
            #[cfg(not(feature = "zklogin"))]
            (MultisigMemberPublicKey::ZkLogin(_), MultisigMemberSignature::ZkLogin(_)) => Err(
                SignatureError::from_source("support for zklogin is not enabled"),
            ),
            #[cfg(feature = "zklogin")]
            (
                MultisigMemberPublicKey::ZkLogin(zklogin_identifier),
                MultisigMemberSignature::ZkLogin(zklogin_authenticator),
            ) => {
                let zklogin_verifier = self
                    .zklogin_verifier()
                    .ok_or_else(|| SignatureError::from_source("no zklogin verifier provided"))?;

                // verify that the member identifier and the authenticator match
                if zklogin_identifier != zklogin_authenticator.inputs.public_identifier() {
                    return Err(SignatureError::from_source(
                        "member zklogin identifier does not match signature",
                    ));
                }

                zklogin_verifier.verify(message, zklogin_authenticator.as_ref())
            }

            _ => Err(SignatureError::from_source(
                "member and signature scheme do not match",
            )),
        }
    }
}

#[cfg(feature = "zklogin")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "zklogin")))]
impl MultisigVerifier {
    pub fn with_zklogin_verifier(&mut self, zklogin_verifier: crate::zklogin::ZkloginVerifier) {
        self.zklogin_verifier = Some(zklogin_verifier);
    }

    pub fn zklogin_verifier(&self) -> Option<&crate::zklogin::ZkloginVerifier> {
        self.zklogin_verifier.as_ref()
    }

    pub fn zklogin_verifier_mut(&mut self) -> Option<&mut crate::zklogin::ZkloginVerifier> {
        self.zklogin_verifier.as_mut()
    }
}

impl Verifier<MultisigAggregatedSignature> for MultisigVerifier {
    fn verify(
        &self,
        message: &[u8],
        signature: &MultisigAggregatedSignature,
    ) -> Result<(), SignatureError> {
        if !signature.committee().is_valid() {
            return Err(SignatureError::from_source("invalid MultisigCommittee"));
        }

        if signature.signatures().len() != signature.bitmap().count_ones() as usize {
            return Err(SignatureError::from_source(
                "number of signatures does not match bitmap",
            ));
        }

        if signature.signatures().len() > signature.committee().members().len() {
            return Err(SignatureError::from_source(
                "more signatures than committee members",
            ));
        }

        let weight = BitmapIndices::new(signature.bitmap())
            .map(|member_idx| {
                signature
                    .committee()
                    .members()
                    .get(member_idx as usize)
                    .ok_or_else(|| SignatureError::from_source("invalid bitmap"))
            })
            .zip(signature.signatures())
            .map(|(maybe_member, signature)| {
                let member = maybe_member?;
                self.verify_member_signature(message, member.public_key(), signature)
                    .map(|()| member.weight() as u16)
            })
            .sum::<Result<u16, SignatureError>>()?;

        if weight >= signature.committee().threshold() {
            Ok(())
        } else {
            Err(SignatureError::from_source(
                "signature weight does not exceed threshold",
            ))
        }
    }
}

impl Verifier<UserSignature> for MultisigVerifier {
    fn verify(&self, message: &[u8], signature: &UserSignature) -> Result<(), SignatureError> {
        let UserSignature::Multisig(signature) = signature else {
            return Err(SignatureError::from_source("not a multisig signature"));
        };

        self.verify(message, signature)
    }
}

/// Interpret a bitmap of 01s as a list of indices that is set to 1s.
/// e.g. 22 = 0b10110, then the result is [1, 2, 4].
struct BitmapIndices {
    bitmap: u16,
    range: std::ops::Range<u8>,
}

impl BitmapIndices {
    pub fn new(bitmap: u16) -> Self {
        Self {
            bitmap,
            range: 0..(u16::BITS as u8),
        }
    }
}

impl Iterator for BitmapIndices {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        #[allow(clippy::while_let_on_iterator)]
        while let Some(i) = self.range.next() {
            if self.bitmap & (1 << i) != 0 {
                return Some(i);
            }
        }

        None
    }
}

/// Verifier that will verify all UserSignature variants
#[derive(Default, Debug, Clone, PartialEq)]
pub struct UserSignatureVerifier {
    inner: MultisigVerifier,
}

impl UserSignatureVerifier {
    pub fn new() -> Self {
        Default::default()
    }
}

#[cfg(feature = "zklogin")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "zklogin")))]
impl UserSignatureVerifier {
    pub fn with_zklogin_verifier(&mut self, zklogin_verifier: crate::zklogin::ZkloginVerifier) {
        self.inner.with_zklogin_verifier(zklogin_verifier);
    }

    pub fn zklogin_verifier(&self) -> Option<&crate::zklogin::ZkloginVerifier> {
        self.inner.zklogin_verifier()
    }

    pub fn zklogin_verifier_mut(&mut self) -> Option<&mut crate::zklogin::ZkloginVerifier> {
        self.inner.zklogin_verifier_mut()
    }
}

impl Verifier<UserSignature> for UserSignatureVerifier {
    fn verify(&self, message: &[u8], signature: &UserSignature) -> Result<(), SignatureError> {
        match signature {
            UserSignature::Simple(signature) => {
                crate::simple::SimpleVerifier.verify(message, signature)
            }
            UserSignature::Multisig(signature) => self.inner.verify(message, signature),
            #[cfg(not(feature = "zklogin"))]
            UserSignature::ZkLoginAuthenticator(_) => Err(SignatureError::from_source(
                "support for zklogin is not enabled",
            )),
            #[cfg(feature = "zklogin")]
            UserSignature::ZkLoginAuthenticator(authenticator) => {
                let zklogin_verifier = self
                    .zklogin_verifier()
                    .ok_or_else(|| SignatureError::from_source("no zklogin verifier provided"))?;

                zklogin_verifier.verify(message, authenticator.as_ref())
            }
            #[cfg(not(feature = "passkey"))]
            UserSignature::PasskeyAuthenticator(_) => Err(SignatureError::from_source(
                "support for passkey is not enabled",
            )),
            #[cfg(feature = "passkey")]
            UserSignature::PasskeyAuthenticator(authenticator) => {
                crate::passkey::PasskeyVerifier::default().verify(message, authenticator)
            }
            UserSignature::MoveAuthenticator(_) => Err(SignatureError::from_source(
                "move authenticators cannot be verified",
            )),
            _ => Err(SignatureError::from_source("unknown signature scheme")),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MultisigAggregator {
    committee: MultisigCommittee,
    signatures: std::collections::BTreeMap<usize, MultisigMemberSignature>,
    signed_weight: u16,
    message: Vec<u8>,
    verifier: MultisigVerifier,
}

impl MultisigAggregator {
    pub fn new_with_transaction(
        committee: MultisigCommittee,
        transaction: &iota_types::Transaction,
    ) -> Self {
        Self {
            committee,
            signatures: Default::default(),
            signed_weight: 0,
            message: transaction.signing_digest().to_vec(),
            verifier: Default::default(),
        }
    }

    pub fn new_with_message(
        committee: MultisigCommittee,
        message: &iota_types::PersonalMessage<'_>,
    ) -> Self {
        Self {
            committee,
            signatures: Default::default(),
            signed_weight: 0,
            message: message.signing_digest().to_vec(),
            verifier: Default::default(),
        }
    }

    pub fn verifier(&self) -> &MultisigVerifier {
        &self.verifier
    }

    pub fn verifier_mut(&mut self) -> &mut MultisigVerifier {
        &mut self.verifier
    }

    pub fn add_signature(&mut self, signature: UserSignature) -> Result<(), SignatureError> {
        use std::collections::btree_map::Entry;

        let (public_key, signature) = multisig_pubkey_and_signature_from_user_signature(signature)?;
        let member_idx = self
            .committee
            .members()
            .iter()
            .position(|member| member.public_key() == &public_key)
            .ok_or_else(|| {
                SignatureError::from_source(
                    "provided signature does not belong to committee member",
                )
            })?;

        self.verifier()
            .verify_member_signature(&self.message, &public_key, &signature)?;

        match self.signatures.entry(member_idx) {
            Entry::Vacant(v) => {
                v.insert(signature);
            }
            Entry::Occupied(_) => {
                return Err(SignatureError::from_source(
                    "duplicate signature from same committee member",
                ));
            }
        }

        self.signed_weight += self.committee.members()[member_idx].weight() as u16;

        Ok(())
    }

    pub fn finish(&self) -> Result<MultisigAggregatedSignature, SignatureError> {
        if self.signed_weight < self.committee.threshold() {
            return Err(SignatureError::from_source(
                "insufficient signature weight to reach threshold",
            ));
        }

        let (signatures, bitmap) = self.signatures.clone().into_iter().fold(
            (Vec::new(), 0),
            |(mut signatures, mut bitmap), (member_idx, signature)| {
                bitmap |= 1 << member_idx;
                signatures.push(signature);
                (signatures, bitmap)
            },
        );

        Ok(MultisigAggregatedSignature::new(
            self.committee.clone(),
            signatures,
            bitmap,
        ))
    }
}

fn multisig_pubkey_and_signature_from_user_signature(
    signature: UserSignature,
) -> Result<(MultisigMemberPublicKey, MultisigMemberSignature), SignatureError> {
    use iota_types::SimpleSignature;
    match signature {
        UserSignature::Simple(SimpleSignature::Ed25519 {
            signature,
            public_key,
        }) => Ok((
            MultisigMemberPublicKey::Ed25519(public_key),
            MultisigMemberSignature::Ed25519(signature),
        )),
        UserSignature::Simple(SimpleSignature::Secp256k1 {
            signature,
            public_key,
        }) => Ok((
            MultisigMemberPublicKey::Secp256k1(public_key),
            MultisigMemberSignature::Secp256k1(signature),
        )),
        UserSignature::Simple(SimpleSignature::Secp256r1 {
            signature,
            public_key,
        }) => Ok((
            MultisigMemberPublicKey::Secp256r1(public_key),
            MultisigMemberSignature::Secp256r1(signature),
        )),
        #[cfg(not(feature = "zklogin"))]
        UserSignature::ZkLoginAuthenticator(_) => Err(SignatureError::from_source(
            "support for zklogin is not enabled",
        )),
        #[cfg(feature = "zklogin")]
        UserSignature::ZkLoginAuthenticator(zklogin_authenticator) => {
            let zklogin_identifier = zklogin_authenticator.inputs.public_identifier().to_owned();
            Ok((
                MultisigMemberPublicKey::ZkLogin(zklogin_identifier),
                MultisigMemberSignature::ZkLogin(zklogin_authenticator),
            ))
        }

        UserSignature::Multisig(_)
        | UserSignature::PasskeyAuthenticator(_)
        | UserSignature::MoveAuthenticator(_) => {
            Err(SignatureError::from_source("invalid signature scheme"))
        }
        _ => Err(SignatureError::from_source("unknown signature scheme")),
    }
}

#[cfg(test)]
mod tests {
    use iota_types::{Ed25519PublicKey, MultisigMember, MultisigMemberPublicKey, PersonalMessage};

    use super::*;

    fn make_member(byte: u8, weight: u8) -> MultisigMember {
        MultisigMember::new(
            MultisigMemberPublicKey::Ed25519(Ed25519PublicKey::new([byte; 32])),
            weight,
        )
    }

    #[test]
    fn bitmap_indices_empty() {
        let indices: Vec<u8> = BitmapIndices::new(0).collect();
        assert!(indices.is_empty());
    }

    #[test]
    fn bitmap_indices_single_bit() {
        let indices: Vec<u8> = BitmapIndices::new(0b0001).collect();
        assert_eq!(indices, vec![0]);
    }

    #[test]
    fn bitmap_indices_multiple_bits() {
        // 0b10110 = 22, bits 1, 2, 4 are set
        let indices: Vec<u8> = BitmapIndices::new(0b10110).collect();
        assert_eq!(indices, vec![1, 2, 4]);
    }

    #[test]
    fn bitmap_indices_10_bits() {
        let bitmap: u16 = 0b1111111111; // first 10 bits
        let indices: Vec<u8> = BitmapIndices::new(bitmap).collect();
        assert_eq!(indices, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn verify_invalid_committee() {
        let verifier = MultisigVerifier::new();
        // Empty committee is invalid
        let committee = MultisigCommittee::new(vec![], 1);
        let sig = MultisigAggregatedSignature::new(committee, vec![], 0);
        let result = verifier.verify(b"msg", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn verify_bitmap_sig_count_mismatch() {
        let verifier = MultisigVerifier::new();
        let committee = MultisigCommittee::new(vec![make_member(1, 1)], 1);
        // bitmap has bit 0 set (1 signature expected) but no signatures provided
        let sig = MultisigAggregatedSignature::new(committee, vec![], 0b1);
        let result = verifier.verify(b"msg", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn verify_more_sigs_than_members() {
        let verifier = MultisigVerifier::new();
        let committee = MultisigCommittee::new(vec![make_member(1, 1)], 1);
        // Create fake ed25519 signatures
        let fake_sigs = vec![
            MultisigMemberSignature::Ed25519(iota_types::Ed25519Signature::new([0; 64])),
            MultisigMemberSignature::Ed25519(iota_types::Ed25519Signature::new([0; 64])),
        ];
        let sig = MultisigAggregatedSignature::new(committee, fake_sigs, 0b11);
        let result = verifier.verify(b"msg", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn verifier_rejects_non_multisig_user_signature() {
        let verifier = MultisigVerifier::new();
        let fake_simple = iota_types::UserSignature::Simple(iota_types::SimpleSignature::Ed25519 {
            signature: iota_types::Ed25519Signature::new([0; 64]),
            public_key: Ed25519PublicKey::new([0; 32]),
        });
        let result: Result<(), _> =
            <MultisigVerifier as Verifier<UserSignature>>::verify(&verifier, b"msg", &fake_simple);
        assert!(result.is_err());
    }

    #[test]
    fn aggregator_sign_and_verify_roundtrip() {
        use crate::{IotaSigner, ed25519::Ed25519PrivateKey};

        let key1 = Ed25519PrivateKey::new([1u8; 32]);
        let key2 = Ed25519PrivateKey::new([2u8; 32]);

        let committee = MultisigCommittee::new(
            vec![
                MultisigMember::new(MultisigMemberPublicKey::Ed25519(key1.public_key()), 1),
                MultisigMember::new(MultisigMemberPublicKey::Ed25519(key2.public_key()), 1),
            ],
            2,
        );

        let message = PersonalMessage(b"hello".to_vec().into());
        let mut aggregator = MultisigAggregator::new_with_message(committee.clone(), &message);

        let sig1 = key1.sign_personal_message(&message).unwrap();
        let sig2 = key2.sign_personal_message(&message).unwrap();

        aggregator.add_signature(sig1).unwrap();
        aggregator.add_signature(sig2).unwrap();

        let multisig = aggregator.finish().unwrap();

        let verifier = MultisigVerifier::new();
        verifier
            .verify(&message.signing_digest(), &multisig)
            .unwrap();
    }

    #[test]
    fn aggregator_non_member_rejected() {
        use crate::{IotaSigner, ed25519::Ed25519PrivateKey};

        let member_key = Ed25519PrivateKey::new([1u8; 32]);
        let non_member_key = Ed25519PrivateKey::new([99u8; 32]);

        let committee = MultisigCommittee::new(
            vec![MultisigMember::new(
                MultisigMemberPublicKey::Ed25519(member_key.public_key()),
                1,
            )],
            1,
        );

        let message = PersonalMessage(b"hello".to_vec().into());
        let mut aggregator = MultisigAggregator::new_with_message(committee, &message);

        let sig = non_member_key.sign_personal_message(&message).unwrap();
        assert!(aggregator.add_signature(sig).is_err());
    }

    #[test]
    fn aggregator_duplicate_signature_rejected() {
        use crate::{IotaSigner, ed25519::Ed25519PrivateKey};

        let key = Ed25519PrivateKey::new([1u8; 32]);

        let committee = MultisigCommittee::new(
            vec![MultisigMember::new(
                MultisigMemberPublicKey::Ed25519(key.public_key()),
                1,
            )],
            1,
        );

        let message = PersonalMessage(b"hello".to_vec().into());
        let mut aggregator = MultisigAggregator::new_with_message(committee, &message);

        let sig1 = key.sign_personal_message(&message).unwrap();
        let sig2 = key.sign_personal_message(&message).unwrap();

        aggregator.add_signature(sig1).unwrap();
        assert!(aggregator.add_signature(sig2).is_err());
    }

    #[test]
    fn aggregator_insufficient_weight() {
        use crate::{IotaSigner, ed25519::Ed25519PrivateKey};

        let key1 = Ed25519PrivateKey::new([1u8; 32]);
        let key2 = Ed25519PrivateKey::new([2u8; 32]);

        let committee = MultisigCommittee::new(
            vec![
                MultisigMember::new(MultisigMemberPublicKey::Ed25519(key1.public_key()), 1),
                MultisigMember::new(MultisigMemberPublicKey::Ed25519(key2.public_key()), 1),
            ],
            2,
        );

        let message = PersonalMessage(b"hello".to_vec().into());
        let mut aggregator = MultisigAggregator::new_with_message(committee, &message);

        let sig = key1.sign_personal_message(&message).unwrap();
        aggregator.add_signature(sig).unwrap();

        // Only weight=1, but threshold=2
        assert!(aggregator.finish().is_err());
    }
}
