// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    borrow::Cow,
    sync::{Arc, RwLock},
};

use iota_sdk::crypto::Verifier;

use crate::{
    error::Result,
    types::{
        crypto::multisig::{MultisigAggregatedSignature, MultisigCommittee},
        signature::UserSignature,
        transaction::Transaction,
    },
};

#[derive(Debug, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct MultisigVerifier(pub RwLock<iota_sdk::crypto::multisig::MultisigVerifier>);

impl From<iota_sdk::crypto::multisig::MultisigVerifier> for MultisigVerifier {
    fn from(verifier: iota_sdk::crypto::multisig::MultisigVerifier) -> Self {
        Self(RwLock::new(verifier))
    }
}

#[uniffi::export]
impl MultisigVerifier {
    #[uniffi::constructor]
    pub fn new() -> Self {
        iota_sdk::crypto::multisig::MultisigVerifier::new().into()
    }

    /// Reject partially signed multisigs whose committee mixes Ed25519 with
    /// other key schemes. Such a multisig is still accepted when every member
    /// has signed. `MultisigAggregator::finish` applies the same rule through
    /// its verifier.
    ///
    /// Enabled by default. The network accepted such multisigs before protocol
    /// version 39 (node release 1.35), so disabling it accepts them again, but
    /// a partially signed one can then not be told apart from one forged
    /// through a committee whose address collides with the signer's.
    pub fn with_reject_partially_signed_mixed_ed25519(self: Arc<Self>, reject: bool) -> Arc<Self> {
        {
            let mut lock = self.0.write().expect("error writing to verifier");
            *lock = std::mem::take(&mut *lock).with_reject_partially_signed_mixed_ed25519(reject);
        }
        self
    }

    pub fn verify(&self, message: &[u8], signature: &MultisigAggregatedSignature) -> Result<()> {
        Ok(self
            .0
            .read()
            .expect("error reading verifier")
            .verify(message, &signature.0)?)
    }
}

/// Verifier that will verify all UserSignature variants
#[derive(Debug, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct UserSignatureVerifier(pub RwLock<iota_sdk::crypto::multisig::UserSignatureVerifier>);

impl From<iota_sdk::crypto::multisig::UserSignatureVerifier> for UserSignatureVerifier {
    fn from(verifier: iota_sdk::crypto::multisig::UserSignatureVerifier) -> Self {
        Self(RwLock::new(verifier))
    }
}

#[uniffi::export]
impl UserSignatureVerifier {
    #[uniffi::constructor]
    pub fn new() -> Self {
        iota_sdk::crypto::multisig::UserSignatureVerifier::new().into()
    }

    /// Reject partially signed multisigs whose committee mixes Ed25519 with
    /// other key schemes. Such a multisig is still accepted when every member
    /// has signed.
    ///
    /// Enabled by default. The network accepted such multisigs before protocol
    /// version 39 (node release 1.35), so disabling it accepts them again, but
    /// a partially signed one can then not be told apart from one forged
    /// through a committee whose address collides with the signer's.
    pub fn with_reject_partially_signed_mixed_ed25519(self: Arc<Self>, reject: bool) -> Arc<Self> {
        {
            let mut lock = self.0.write().expect("error writing to verifier");
            *lock = std::mem::take(&mut *lock).with_reject_partially_signed_mixed_ed25519(reject);
        }
        self
    }

    pub fn verify(&self, message: &[u8], signature: &UserSignature) -> Result<()> {
        Ok(self
            .0
            .read()
            .expect("error reading verifier")
            .verify(message, &signature.0)?)
    }
}

#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct MultisigAggregator(pub RwLock<iota_sdk::crypto::multisig::MultisigAggregator>);

#[uniffi::export]
impl MultisigAggregator {
    #[uniffi::constructor]
    pub fn new_with_transaction(committee: &MultisigCommittee, transaction: &Transaction) -> Self {
        Self(
            iota_sdk::crypto::multisig::MultisigAggregator::new_with_transaction(
                committee.0.clone(),
                &transaction.0,
            )
            .into(),
        )
    }

    #[uniffi::constructor]
    pub fn new_with_message(committee: &MultisigCommittee, message: &[u8]) -> Self {
        Self(
            iota_sdk::crypto::multisig::MultisigAggregator::new_with_message(
                committee.0.clone(),
                &iota_sdk::types::PersonalMessage(Cow::Borrowed(message)),
            )
            .into(),
        )
    }

    pub fn verifier(&self) -> MultisigVerifier {
        self.0
            .read()
            .expect("failed to read multisig aggregator")
            .verifier()
            .clone()
            .into()
    }

    pub fn set_verifier(&self, verifier: &MultisigVerifier) {
        *self
            .0
            .write()
            .expect("failed to write multisig aggregator")
            .verifier_mut() = verifier.0.read().expect("error reading verifier").clone();
    }

    pub fn add_signature(&self, signature: &UserSignature) -> Result<()> {
        Ok(self
            .0
            .write()
            .expect("failed to write multisig aggregator")
            .add_signature(signature.0.clone())?)
    }

    pub fn finish(&self) -> Result<MultisigAggregatedSignature> {
        Ok(self
            .0
            .read()
            .expect("failed to read multisig aggregator")
            .finish()?
            .into())
    }
}
