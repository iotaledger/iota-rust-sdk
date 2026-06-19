// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::{
    Address, MultisigAggregatedSignature, MultisigCommittee, MultisigMemberSignature, PublicKey,
    SignatureScheme, UserSignature, crypto::ThresholdUnit,
};

use crate::{SignatureError, Verifier};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct MultisigVerifier {
    address: Option<Address>,
    #[cfg(feature = "passkey")]
    passkey_verifier: Option<crate::passkey::PasskeyVerifier>,
    accept_passkey_in_multisig: bool,
    additional_multisig_checks: bool,
}

impl MultisigVerifier {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_address(mut self, address: Address) -> Self {
        self.address = Some(address);
        self
    }

    pub fn with_accept_passkey_in_multisig(mut self, accept: bool) -> Self {
        self.accept_passkey_in_multisig = accept;
        self
    }

    pub fn with_additional_multisig_checks(mut self, additional_checks: bool) -> Self {
        self.additional_multisig_checks = additional_checks;
        self
    }

    pub fn verify_member_signature(
        &self,
        message: &[u8],
        member_public_key: &PublicKey,
        signature: &MultisigMemberSignature,
    ) -> Result<(), SignatureError> {
        match (member_public_key, signature) {
            #[cfg(not(feature = "ed25519"))]
            (PublicKey::Ed25519(_), MultisigMemberSignature::Ed25519(_)) => Err(
                SignatureError::from_source("support for ed25519 is not enabled"),
            ),
            #[cfg(feature = "ed25519")]
            (
                PublicKey::Ed25519(ed25519_public_key),
                MultisigMemberSignature::Ed25519(ed25519_signature),
            ) => crate::ed25519::Ed25519VerifyingKey::new(ed25519_public_key)?
                .verify(message, ed25519_signature),
            #[cfg(not(feature = "secp256k1"))]
            (PublicKey::Secp256k1(_), MultisigMemberSignature::Secp256k1(_)) => Err(
                SignatureError::from_source("support for secp256k1 is not enabled"),
            ),
            #[cfg(feature = "secp256k1")]
            (
                PublicKey::Secp256k1(k1_public_key),
                MultisigMemberSignature::Secp256k1(k1_signature),
            ) => crate::secp256k1::Secp256k1VerifyingKey::new(k1_public_key)?
                .verify(message, k1_signature),
            #[cfg(not(feature = "secp256r1"))]
            (PublicKey::Secp256r1(_), MultisigMemberSignature::Secp256r1(_)) => Err(
                SignatureError::from_source("support for secp256r1 is not enabled"),
            ),
            #[cfg(feature = "secp256r1")]
            (
                PublicKey::Secp256r1(r1_public_key),
                MultisigMemberSignature::Secp256r1(r1_signature),
            ) => crate::secp256r1::Secp256r1VerifyingKey::new(r1_public_key)?
                .verify(message, r1_signature),
            #[cfg(not(feature = "passkey"))]
            (PublicKey::Passkey(_), MultisigMemberSignature::Passkey(_)) => Err(
                SignatureError::from_source("support for passkey is not enabled"),
            ),
            #[cfg(feature = "passkey")]
            (
                PublicKey::Passkey(passkey_public_key),
                MultisigMemberSignature::Passkey(passkey_authenticator),
            ) => {
                let passkey_verifier = self.passkey_verifier().cloned().unwrap_or_default();

                // verify that the member public key and the authenticator's key match
                if passkey_public_key != &passkey_authenticator.public_key() {
                    return Err(SignatureError::from_source(
                        "member passkey public key does not match signature",
                    ));
                }

                passkey_verifier.verify(message, passkey_authenticator)
            }
            _ => Err(SignatureError::from_source(
                "member and signature scheme do not match",
            )),
        }
    }
}

#[cfg(feature = "passkey")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "passkey")))]
impl MultisigVerifier {
    pub fn with_passkey_verifier(&mut self, passkey_verifier: crate::passkey::PasskeyVerifier) {
        self.passkey_verifier = Some(passkey_verifier);
    }

    pub fn passkey_verifier(&self) -> Option<&crate::passkey::PasskeyVerifier> {
        self.passkey_verifier.as_ref()
    }

    pub fn passkey_verifier_mut(&mut self) -> Option<&mut crate::passkey::PasskeyVerifier> {
        self.passkey_verifier.as_mut()
    }
}

impl Verifier<MultisigAggregatedSignature> for MultisigVerifier {
    fn verify(
        &self,
        message: &[u8],
        signature: &MultisigAggregatedSignature,
    ) -> Result<(), SignatureError> {
        signature
            .validate()
            .map_err(|e| SignatureError::from_source(format!("invalid multisig: {e}")))?;

        if let Some(address) = &self.address
            && signature.committee().derive_address() != *address
        {
            return Err(SignatureError::from_source(
                "Invalid address derived from pks",
            ));
        }

        if !self.accept_passkey_in_multisig
            && signature.contains_signature_scheme(SignatureScheme::PasskeyAuthenticator)
        {
            return Err(SignatureError::from_source(
                "Passkey sig not supported inside multisig",
            ));
        }

        let mut weight: ThresholdUnit = 0;
        for (member_idx, member_signature) in
            BitmapIndices::new(signature.bitmap()).zip(signature.signatures())
        {
            let member = signature
                .committee()
                .members()
                .get(member_idx as usize)
                .ok_or_else(|| SignatureError::from_source("Invalid public keys index"))?;

            if self.additional_multisig_checks
                && member.public_key().scheme() != member_signature.scheme()
            {
                return Err(SignatureError::from_source(format!(
                    "Invalid sig for pk={} address={:?} error=signature/pubkey type mismatch",
                    member.public_key().to_base64(),
                    member.public_key().derive_address(),
                )));
            }

            self.verify_member_signature(message, member.public_key(), member_signature)
                .map_err(|e| {
                    SignatureError::from_source(format!(
                        "Invalid sig for pk={} address={:?} error={e}",
                        member.public_key().to_base64(),
                        member.public_key().derive_address(),
                    ))
                })?;

            weight = weight
                .checked_add(member.weight() as ThresholdUnit)
                .ok_or(SignatureError::from_source("Weight overflow"))?;
        }

        if weight >= signature.committee().threshold() {
            Ok(())
        } else {
            Err(SignatureError::from_source(format!(
                "Insufficient weight={weight:?} threshold={:?}",
                signature.committee().threshold()
            )))
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
#[derive(Clone, Debug, Default, PartialEq)]
pub struct UserSignatureVerifier {
    inner: MultisigVerifier,
}

impl UserSignatureVerifier {
    pub fn new() -> Self {
        Default::default()
    }
}

#[cfg(feature = "passkey")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "passkey")))]
impl UserSignatureVerifier {
    pub fn with_passkey_verifier(&mut self, passkey_verifier: crate::passkey::PasskeyVerifier) {
        self.inner.with_passkey_verifier(passkey_verifier);
    }

    pub fn passkey_verifier(&self) -> Option<&crate::passkey::PasskeyVerifier> {
        self.inner.passkey_verifier()
    }

    pub fn passkey_verifier_mut(&mut self) -> Option<&mut crate::passkey::PasskeyVerifier> {
        self.inner.passkey_verifier_mut()
    }
}

impl Verifier<UserSignature> for UserSignatureVerifier {
    fn verify(&self, message: &[u8], signature: &UserSignature) -> Result<(), SignatureError> {
        match signature {
            UserSignature::Simple(signature) => {
                crate::simple::SimpleVerifier.verify(message, signature)
            }
            UserSignature::Multisig(signature) => self.inner.verify(message, signature),
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

#[derive(Clone, Debug, PartialEq)]
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

        self.signed_weight = self
            .signed_weight
            .checked_add(self.committee.members()[member_idx].weight() as ThresholdUnit)
            .ok_or_else(|| SignatureError::from_source("signed weight overflow"))?;

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

        Ok(MultisigAggregatedSignature::new_unchecked(
            signatures,
            bitmap,
            self.committee.clone(),
        ))
    }
}

fn multisig_pubkey_and_signature_from_user_signature(
    signature: UserSignature,
) -> Result<(PublicKey, MultisigMemberSignature), SignatureError> {
    use iota_types::SimpleSignature;
    match signature {
        UserSignature::Simple(SimpleSignature::Ed25519 {
            signature,
            public_key,
        }) => Ok((public_key.into(), signature.into())),
        UserSignature::Simple(SimpleSignature::Secp256k1 {
            signature,
            public_key,
        }) => Ok((public_key.into(), signature.into())),
        UserSignature::Simple(SimpleSignature::Secp256r1 {
            signature,
            public_key,
        }) => Ok((public_key.into(), signature.into())),
        UserSignature::PasskeyAuthenticator(passkey_authenticator) => Ok((
            passkey_authenticator.clone().into(),
            passkey_authenticator.into(),
        )),
        UserSignature::Multisig(_) | UserSignature::MoveAuthenticator(_) => {
            Err(SignatureError::from_source("invalid signature scheme"))
        }
        _ => Err(SignatureError::from_source("unknown signature scheme")),
    }
}
