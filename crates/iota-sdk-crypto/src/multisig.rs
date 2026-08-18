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

        let indices = signature
            .indices()
            .map_err(|e| SignatureError::from_source(format!("invalid multisig: {e}")))?;

        let mut weight: ThresholdUnit = 0;
        for (member_idx, member_signature) in indices.into_iter().zip(signature.signatures()) {
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

#[cfg(test)]
mod tests {
    use base64ct::{Base64, Encoding};
    use iota_types::{
        Address, MultisigAggregatedSignature, MultisigCommittee, MultisigMember,
        MultisigMemberSignature, PersonalMessage, PublicKey, Transaction, UserSignature,
    };

    use super::{MultisigAggregator, MultisigVerifier, UserSignatureVerifier};
    use crate::{
        IotaSigner, IotaVerifier, ed25519::Ed25519PrivateKey, secp256k1::Secp256k1PrivateKey,
        secp256r1::Secp256r1PrivateKey,
    };

    /// `signature::Error`'s `Display` is deliberately opaque, so the message a
    /// verifier attached is only reachable through the source chain.
    fn error_chain(error: &crate::SignatureError) -> String {
        let mut out = error.to_string();
        let mut source = std::error::Error::source(error);
        while let Some(cause) = source {
            out.push_str(": ");
            out.push_str(&cause.to_string());
            source = cause.source();
        }
        out
    }

    /// Three deterministic private keys, one per supported signature scheme.
    fn test_keys() -> (Ed25519PrivateKey, Secp256k1PrivateKey, Secp256r1PrivateKey) {
        (
            Ed25519PrivateKey::new([1u8; 32]),
            Secp256k1PrivateKey::new([2u8; 32]).unwrap(),
            Secp256r1PrivateKey::new([3u8; 32]).unwrap(),
        )
    }

    /// A 2-of-3 committee with one member per scheme, each with weight 1.
    fn committee_2_of_3(
        k0: &Ed25519PrivateKey,
        k1: &Secp256k1PrivateKey,
        k2: &Secp256r1PrivateKey,
    ) -> MultisigCommittee {
        MultisigCommittee::new(
            vec![
                MultisigMember::new(PublicKey::Ed25519(k0.public_key()), 1),
                MultisigMember::new(PublicKey::Secp256k1(k1.public_key()), 1),
                MultisigMember::new(PublicKey::Secp256r1(k2.public_key()), 1),
            ],
            2,
        )
        .unwrap()
    }

    fn message() -> PersonalMessage<'static> {
        PersonalMessage("hello multisig".as_bytes().to_vec().into())
    }

    /// Sign with two of the three members and verify the aggregated signature
    /// both with the generic verifier and with the multisig address bound.
    #[test]
    fn sign_aggregate_and_verify() {
        let (k0, k1, k2) = test_keys();
        let committee = committee_2_of_3(&k0, &k1, &k2);
        let msg = message();

        // Members 0 and 2, provided in committee order.
        let sig0 = k0.sign_personal_message(&msg).unwrap();
        let sig2 = k2.sign_personal_message(&msg).unwrap();
        let aggregated =
            MultisigAggregatedSignature::new(vec![sig0, sig2], committee.clone()).unwrap();
        let user_signature = UserSignature::Multisig(aggregated);

        UserSignatureVerifier::new()
            .verify_personal_message(&msg, &user_signature)
            .unwrap();

        MultisigVerifier::new()
            .with_address(committee.derive_address())
            .verify_personal_message(&msg, &user_signature)
            .unwrap();
    }

    /// A signed weight below the committee threshold must be rejected.
    #[test]
    fn verify_rejects_insufficient_weight() {
        let (k0, k1, k2) = test_keys();
        let committee = committee_2_of_3(&k0, &k1, &k2);
        let msg = message();

        // Only one of the two required signatures.
        let sig0 = k0.sign_personal_message(&msg).unwrap();
        let aggregated = MultisigAggregatedSignature::new(vec![sig0], committee).unwrap();

        let error = UserSignatureVerifier::new()
            .verify_personal_message(&msg, &UserSignature::Multisig(aggregated))
            .unwrap_err();
        assert!(
            error_chain(&error).contains("Insufficient weight"),
            "expected an insufficient-weight error, got {}",
            error_chain(&error)
        );
    }

    /// Binding the wrong address must be rejected even when the signatures
    /// themselves are valid.
    #[test]
    fn verify_rejects_wrong_address() {
        let (k0, k1, k2) = test_keys();
        let committee = committee_2_of_3(&k0, &k1, &k2);
        let msg = message();

        let sig0 = k0.sign_personal_message(&msg).unwrap();
        let sig2 = k2.sign_personal_message(&msg).unwrap();
        let aggregated = MultisigAggregatedSignature::new(vec![sig0, sig2], committee).unwrap();

        let error = MultisigVerifier::new()
            .with_address(Address::ZERO)
            .verify_personal_message(&msg, &UserSignature::Multisig(aggregated))
            .unwrap_err();
        assert!(
            error_chain(&error).contains("Invalid address derived from pks"),
            "expected an invalid-address error, got {}",
            error_chain(&error)
        );
    }

    /// When a member signature's scheme does not match its committee public
    /// key, the mismatch is only reported when the additional multisig checks
    /// are enabled; otherwise the failure surfaces later, during cryptographic
    /// verification.
    #[test]
    fn verify_reports_scheme_pubkey_mismatch_only_with_additional_checks() {
        let (k0, k1, _k2) = test_keys();
        let msg = message();

        // Committee with a single Ed25519 member.
        let committee = MultisigCommittee::new(
            vec![MultisigMember::new(PublicKey::Ed25519(k0.public_key()), 1)],
            1,
        )
        .unwrap();

        // ...but the accompanying member signature is Secp256k1.
        let secp_member_signature =
            MultisigMemberSignature::try_from(k1.sign_personal_message(&msg).unwrap()).unwrap();
        let aggregated =
            MultisigAggregatedSignature::new_unchecked(vec![secp_member_signature], 0b1, committee);
        let user_signature = UserSignature::Multisig(aggregated);

        let error = MultisigVerifier::new()
            .with_additional_multisig_checks(true)
            .verify_personal_message(&msg, &user_signature)
            .unwrap_err();
        assert!(
            error_chain(&error).contains("signature/pubkey type mismatch"),
            "expected an explicit scheme mismatch error, got {}",
            error_chain(&error)
        );

        let error = MultisigVerifier::new()
            .with_additional_multisig_checks(false)
            .verify_personal_message(&msg, &user_signature)
            .unwrap_err();
        assert!(
            !error_chain(&error).contains("signature/pubkey type mismatch"),
            "the scheme mismatch must only be checked with additional checks enabled, got {}",
            error_chain(&error)
        );
    }

    /// Drive the incremental [`MultisigAggregator`]: duplicates and
    /// non-members are rejected, `finish` enforces the threshold, and the
    /// resulting signature verifies.
    #[test]
    fn aggregator_rejects_bad_signatures_and_enforces_threshold() {
        let (k0, k1, k2) = test_keys();
        let committee = committee_2_of_3(&k0, &k1, &k2);
        let msg = message();

        let mut aggregator = MultisigAggregator::new_with_message(committee, &msg);
        aggregator
            .add_signature(k0.sign_personal_message(&msg).unwrap())
            .unwrap();

        // The same member signing twice is rejected.
        let error = aggregator
            .add_signature(k0.sign_personal_message(&msg).unwrap())
            .unwrap_err();
        assert!(
            error_chain(&error).contains("duplicate signature"),
            "expected a duplicate-signature error, got {}",
            error_chain(&error)
        );

        // A signer outside the committee is rejected.
        let outsider = Ed25519PrivateKey::new([9u8; 32]);
        let error = aggregator
            .add_signature(outsider.sign_personal_message(&msg).unwrap())
            .unwrap_err();
        assert!(
            error_chain(&error).contains("does not belong to committee member"),
            "expected a non-member error, got {}",
            error_chain(&error)
        );

        // Still one short of the threshold.
        let error = aggregator.finish().unwrap_err();
        assert!(
            error_chain(&error).contains("insufficient signature weight"),
            "expected an insufficient-weight error, got {}",
            error_chain(&error)
        );

        // Reaching the threshold yields a signature that verifies.
        aggregator
            .add_signature(k2.sign_personal_message(&msg).unwrap())
            .unwrap();
        let aggregated = aggregator.finish().unwrap();
        UserSignatureVerifier::new()
            .verify_personal_message(&msg, &UserSignature::Multisig(aggregated))
            .unwrap();
    }

    /// [`UserSignatureVerifier`] accepts a plain simple signature, while the
    /// [`MultisigVerifier`] rejects anything that is not a multisig.
    #[test]
    fn user_signature_verifier_handles_simple_signatures() {
        let (k0, _k1, _k2) = test_keys();
        let msg = message();
        let signature = k0.sign_personal_message(&msg).unwrap();

        UserSignatureVerifier::new()
            .verify_personal_message(&msg, &signature)
            .unwrap();

        let error = MultisigVerifier::new()
            .verify_personal_message(&msg, &signature)
            .unwrap_err();
        assert!(
            error_chain(&error).contains("not a multisig"),
            "expected a not-a-multisig error, got {}",
            error_chain(&error)
        );
    }

    /// A passkey member inside a multisig is rejected unless explicitly
    /// accepted, independent of whether its signature would verify.
    #[cfg(feature = "passkey")]
    #[test]
    fn verify_rejects_passkey_member_when_not_accepted() {
        const PASSKEY: &str = "BiVYDmenOnqS+thmz5m5SrZnWaKXZLVxgh+rri6LHXs25B0AAAAAnQF7InR5cGUiOiJ3ZWJhdXRobi5nZXQiLCAiY2hhbGxlbmdlIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTE3MyIsImNyb3NzT3JpZ2luIjpmYWxzZSwgInVua25vd24iOiAidW5rbm93biJ9YgJMwqcOmZI7F/N+K5SMe4DRYCb4/cDWW68SFneSHoD2GxKKhksbpZ5rZpdrjSYABTCsFQQBpLORzTvbj4edWKd/AsEBeovrGvHR9Ku7critg6k7qvfFlPUngujXfEzXd8Eg";
        let UserSignature::PasskeyAuthenticator(authenticator) =
            UserSignature::from_base64(PASSKEY).unwrap()
        else {
            panic!("expected a passkey authenticator");
        };

        let committee = MultisigCommittee::new(
            vec![MultisigMember::new(
                PublicKey::Passkey(authenticator.public_key()),
                1,
            )],
            1,
        )
        .unwrap();
        let aggregated = MultisigAggregatedSignature::new_unchecked(
            vec![MultisigMemberSignature::Passkey(authenticator)],
            0b1,
            committee,
        );

        let error = MultisigVerifier::new()
            .verify_personal_message(&message(), &UserSignature::Multisig(aggregated))
            .unwrap_err();
        assert!(
            error_chain(&error).contains("Passkey sig not supported inside multisig"),
            "expected a passkey-not-supported error, got {}",
            error_chain(&error)
        );
    }

    /// Decode a hardcoded base64 transaction and the 2-of-3 multisig signature
    /// over it (ed25519 + secp256k1), then verify. This pins the multisig wire
    /// format and end-to-end verification, mirroring the fixtures kept for the
    /// other signature schemes.
    #[test]
    fn transaction_signing_fixture() {
        const TRANSACTION: &str = "AAAAACdZawPnpJRjmVcwDu6xrIumtq5NLO+6GHbs0iGdCoD7AQ0T0TolicYERdSvyCRjSSduDZLbSpBsZBoib+lF48EBcgAAAAAAAAAgpQr/Mudl9BdzyBdkbqTlqBw4/aJ21kAD/jpJKa05im4nWWsD56SUY5lXMA7usayLprauTSzvuhh27NIhnQqA++gDAAAAAAAAgIQeAAAAAAAA";
        const SIGNATURE: &str = "AwIAmKdbsCv3twpuIZxcthshGGTFG7hiE2fQw91w/DZrf5A+AA3e9IQckiYIX49t90Yt35TcAL+/SDn59qFGEUWFBQEylmEdd1gN3vl+qdtlk0URXk3d7olacAUBy/fqEdnfKxrQzP6ElAcVrhNLuIXC5TwRphTi7xMkuiZaWPrDlLKBAwADAIqI4910CfGV/VLbLTy6XXLKZwm/HZQSG/N0iAG0D29cAQECTUts0TYQMsqb0q652QCqTUXZ6tgKyUIzdMRRpyVNB2YBAgJZGrdx67z9bZy5CU0QZSit0aadRMLB9ifwiexYucYa3wECAA==";

        let transaction: Transaction = {
            let bytes = Base64::decode_vec(TRANSACTION).unwrap();
            bcs::from_bytes(&bytes).unwrap()
        };
        let signature = UserSignature::from_base64(SIGNATURE).unwrap();

        let UserSignature::Multisig(aggregated) = &signature else {
            panic!("expected a multisig signature");
        };
        assert_eq!(
            aggregated.committee().derive_address(),
            Address::from_hex("0x2ca61f76b5f08a1015fee1a80eb2421b604e68872d97dec2f620a4a1b34e7811")
                .unwrap(),
        );

        UserSignatureVerifier::new()
            .verify_transaction(&transaction, &signature)
            .unwrap();

        MultisigVerifier::new()
            .with_address(aggregated.committee().derive_address())
            .verify_transaction(&transaction, &signature)
            .unwrap();
    }
}
