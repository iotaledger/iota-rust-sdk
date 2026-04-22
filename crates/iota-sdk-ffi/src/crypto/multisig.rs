// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;

use iota_sdk::crypto::Verifier;

use crate::{
    error::Result,
    types::{
        crypto::multisig::{MultisigAggregatedSignature, MultisigCommittee},
        signature::UserSignature,
        transaction::Transaction,
    },
};

#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct MultisigVerifier(pub iota_sdk::crypto::multisig::MultisigVerifier);

#[uniffi::export]
impl MultisigVerifier {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self(iota_sdk::crypto::multisig::MultisigVerifier::new())
    }

    pub fn verify(&self, message: &[u8], signature: &MultisigAggregatedSignature) -> Result<()> {
        Ok(self.0.verify(message, &signature.0)?)
    }
}

/// Verifier that will verify all UserSignature variants
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct UserSignatureVerifier(pub iota_sdk::crypto::multisig::UserSignatureVerifier);

#[uniffi::export]
impl UserSignatureVerifier {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self(iota_sdk::crypto::multisig::UserSignatureVerifier::new())
    }

    pub fn verify(&self, message: &[u8], signature: &UserSignature) -> Result<()> {
        Ok(self.0.verify(message, &signature.0)?)
    }
}

#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct MultisigAggregator(pub iota_sdk::crypto::multisig::MultisigAggregator);

#[uniffi::export]
impl MultisigAggregator {
    #[uniffi::constructor]
    pub fn new_with_transaction(committee: &MultisigCommittee, transaction: &Transaction) -> Self {
        Self(
            iota_sdk::crypto::multisig::MultisigAggregator::new_with_transaction(
                committee.0.clone(),
                &transaction.0,
            ),
        )
    }

    #[uniffi::constructor]
    pub fn new_with_message(committee: &MultisigCommittee, message: &[u8]) -> Self {
        Self(
            iota_sdk::crypto::multisig::MultisigAggregator::new_with_message(
                committee.0.clone(),
                &iota_sdk::types::PersonalMessage(Cow::Borrowed(message)),
            ),
        )
    }

    pub fn verifier(&self) -> MultisigVerifier {
        self.0.verifier().clone().into()
    }

    pub fn with_verifier(&self, verifier: &MultisigVerifier) -> Self {
        let mut aggregator = self.0.clone();
        *aggregator.verifier_mut() = verifier.0.clone();
        Self(aggregator)
    }

    pub fn with_signature(&self, signature: &UserSignature) -> Result<Self> {
        let mut aggregator = self.0.clone();
        aggregator.add_signature(signature.0.clone())?;
        Ok(Self(aggregator))
    }

    pub fn finish(&self) -> Result<MultisigAggregatedSignature> {
        let aggregator = self.0.clone();
        Ok(aggregator.finish()?.into())
    }
}
