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
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    // --- BitmapIndices ---

    #[test]
    fn bitmap_indices_empty_bitmap() {
        let indices: Vec<u8> = BitmapIndices::new(0).collect();
        assert!(indices.is_empty(), "empty bitmap should yield no indices");
    }

    #[test]
    fn bitmap_indices_single_bit() {
        // 0b0001 = bit 0 set
        let indices: Vec<u8> = BitmapIndices::new(1).collect();
        assert_eq!(indices, vec![0]);
    }

    #[test]
    fn bitmap_indices_multiple_bits() {
        // 22 = 0b10110 => bits 1, 2, 4 are set
        let indices: Vec<u8> = BitmapIndices::new(22).collect();
        assert_eq!(indices, vec![1, 2, 4]);
    }

    #[test]
    fn bitmap_indices_all_low_bits() {
        // 0b1111 = 15 => bits 0, 1, 2, 3
        let indices: Vec<u8> = BitmapIndices::new(0b1111).collect();
        assert_eq!(indices, vec![0, 1, 2, 3]);
    }

    #[test]
    fn bitmap_indices_high_bit() {
        // bit 15 set (highest for u16)
        let indices: Vec<u8> = BitmapIndices::new(1 << 15).collect();
        assert_eq!(indices, vec![15]);
    }

    #[test]
    fn bitmap_indices_non_contiguous() {
        // 0b101010101 = bits 0, 2, 4, 6, 8
        let indices: Vec<u8> = BitmapIndices::new(0b101010101).collect();
        assert_eq!(indices, vec![0, 2, 4, 6, 8]);
    }

    #[test]
    fn bitmap_indices_all_bits_set() {
        let indices: Vec<u8> = BitmapIndices::new(u16::MAX).collect();
        let expected: Vec<u8> = (0..16).collect();
        assert_eq!(indices, expected);
    }

    // --- MultisigVerifier / UserSignatureVerifier construction ---

    #[test]
    fn multisig_verifier_default() {
        let v = MultisigVerifier::new();
        let v2 = MultisigVerifier::default();
        assert_eq!(v, v2, "new() and default() should produce identical verifiers");
    }

    #[test]
    fn user_signature_verifier_default() {
        let v = UserSignatureVerifier::new();
        let v2 = UserSignatureVerifier::default();
        assert_eq!(v, v2);
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_multisig_verifier_e2e_ed25519() {
        use rand::rngs::OsRng;
        use crate::ed25519::Ed25519PrivateKey;
        use crate::Signer; // trait
        use iota_types::{
             MultisigMember, MultisigMemberPublicKey, MultisigCommittee, 
             MultisigMemberSignature, MultisigAggregatedSignature
        };

        let msg = b"multisig test message";

        // 1. Generate keys
        let sk1 = Ed25519PrivateKey::generate(&mut OsRng);
        let pk1 = sk1.public_key();
        let sk2 = Ed25519PrivateKey::generate(&mut OsRng);
        let pk2 = sk2.public_key();
        let sk3 = Ed25519PrivateKey::generate(&mut OsRng);
        let pk3 = sk3.public_key();

        // 2. Create Committee (threshold 2)
        let m1 = MultisigMember::new(MultisigMemberPublicKey::Ed25519(pk1), 1);
        let m2 = MultisigMember::new(MultisigMemberPublicKey::Ed25519(pk2), 1);
        let m3 = MultisigMember::new(MultisigMemberPublicKey::Ed25519(pk3), 1);
        
        let committee = MultisigCommittee::new(vec![m1, m2, m3], 2);

        // 3. Sign
        let sig1: iota_types::Ed25519Signature = sk1.try_sign(msg).unwrap();
        let sig2: iota_types::Ed25519Signature = sk2.try_sign(msg).unwrap();
        
        // 4. Create Aggregated Signature
        // Signers are at indices 0 and 1.
        let signatures = vec![
             MultisigMemberSignature::Ed25519(sig1),
             MultisigMemberSignature::Ed25519(sig2),
        ];
        // Bitmap: indices 0 (bit0) and 1 (bit1) -> 0b11 = 3
        let bitmap = 3;
        
        let agg_sig = MultisigAggregatedSignature::new(committee.clone(), signatures, bitmap);

        // 5. Verify
        let verifier = MultisigVerifier::new();
        assert!(verifier.verify(msg, &agg_sig).is_ok());

        // 6. Test Failures
        
        // Bad Message
        assert!(verifier.verify(b"bad msg", &agg_sig).is_err());
        
        // Insufficient Weight (remove sig2)
        // Indices: 0. Bitmap: 1.
        let partial_sigs = vec![
             MultisigMemberSignature::Ed25519(sk1.try_sign(msg).unwrap()),
        ];
        let partial_agg = MultisigAggregatedSignature::new(committee.clone(), partial_sigs, 1);
        assert!(verifier.verify(msg, &partial_agg).is_err()); // Weight 1 < 2
        
        // Mismatched Bitmap (Bitmap says 2 signatures, we provide 1)
        // Bitmap 3 (2 bits), Sig vector len 1.
        let bad_bitmap_sig = MultisigAggregatedSignature::new(committee.clone(), vec![MultisigMemberSignature::Ed25519(sk1.try_sign(msg).unwrap())], 3);
        assert!(verifier.verify(msg, &bad_bitmap_sig).is_err());
        
        // Invalid Member Signature (Signed by random key)
        let sk_random = Ed25519PrivateKey::generate(&mut OsRng);
        let sig_random: iota_types::Ed25519Signature = sk_random.try_sign(msg).unwrap();
        let invalid_sigs = vec![
             MultisigMemberSignature::Ed25519(sk1.try_sign(msg).unwrap()),
             MultisigMemberSignature::Ed25519(sig_random), // Index 1 expects pk2, but we give sig from random
        ];
        let invalid_agg = MultisigAggregatedSignature::new(committee.clone(), invalid_sigs, 3);
        assert!(verifier.verify(msg, &invalid_agg).is_err());
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_multisig_aggregator_workflow() {
        use rand::rngs::OsRng;
        use crate::ed25519::Ed25519PrivateKey;
        use crate::Signer; 
        use iota_types::{
             MultisigMember, MultisigMemberPublicKey, MultisigCommittee, 
             UserSignature // UserSignature enum used by aggregator
        };

        let msg = b"aggregator test";
        let sk1 = Ed25519PrivateKey::generate(&mut OsRng);
        let sk2 = Ed25519PrivateKey::generate(&mut OsRng);
        
        let m1 = MultisigMember::new(MultisigMemberPublicKey::Ed25519(sk1.public_key()), 1);
        let m2 = MultisigMember::new(MultisigMemberPublicKey::Ed25519(sk2.public_key()), 1);
        let committee = MultisigCommittee::new(vec![m1, m2], 2);

        let personal_msg = iota_types::PersonalMessage(msg.into());
        
        let mut aggregator = MultisigAggregator::new_with_message(committee, &personal_msg);
        
        let digest = personal_msg.signing_digest();
        let sig1_user: UserSignature = sk1.try_sign(digest.as_ref()).unwrap();
        let sig2_user: UserSignature = sk2.try_sign(digest.as_ref()).unwrap();
        
        aggregator.add_signature(sig1_user).unwrap();
        assert!(aggregator.finish().is_err()); // Weight 1 < 2
        
        aggregator.add_signature(sig2_user).unwrap();
        let agg_sig = aggregator.finish().unwrap();
        
        // Verify 
        let verifier = MultisigVerifier::new();
        assert!(verifier.verify(digest.as_ref(), &agg_sig).is_ok());
    }
}
