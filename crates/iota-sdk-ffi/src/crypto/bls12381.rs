// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::RwLock;

use iota_types::SignatureScheme;
use rand::rngs::OsRng;

use crate::{
    error::{Result, SdkFfiError},
    types::{
        checkpoint::CheckpointSummary,
        crypto::{
            Bls12381PublicKey, Bls12381Signature,
            validator::{ValidatorAggregatedSignature, ValidatorCommittee, ValidatorSignature},
        },
    },
};

#[derive(derive_more::From, uniffi::Object)]
pub struct Bls12381PrivateKey(pub iota_crypto::bls12381::Bls12381PrivateKey);

#[uniffi::export]
impl Bls12381PrivateKey {
    #[uniffi::constructor]
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        Ok(Self(iota_crypto::bls12381::Bls12381PrivateKey::new(
            bytes.try_into().map_err(|v: Vec<u8>| {
                SdkFfiError::custom(format!("expected bytes of length 32, found {}", v.len()))
            })?,
        )?))
    }

    pub fn scheme(&self) -> SignatureScheme {
        self.0.scheme()
    }

    pub fn verifying_key(&self) -> Bls12381VerifyingKey {
        self.0.verifying_key().into()
    }

    pub fn public_key(&self) -> Bls12381PublicKey {
        self.0.public_key().into()
    }

    #[uniffi::constructor]
    pub fn generate() -> Self {
        Self(iota_crypto::bls12381::Bls12381PrivateKey::generate(OsRng))
    }

    pub fn sign_checkpoint_summary(&self, summary: &CheckpointSummary) -> ValidatorSignature {
        self.0.sign_checkpoint_summary(&summary.0).into()
    }

    pub fn try_sign(&self, message: &[u8]) -> Result<Bls12381Signature> {
        Ok(
            iota_crypto::Signer::<iota_types::Bls12381Signature>::try_sign(&self.0, message)?
                .into(),
        )
    }
}

#[derive(derive_more::From, uniffi::Object)]
pub struct Bls12381VerifyingKey(pub iota_crypto::bls12381::Bls12381VerifyingKey);

#[uniffi::export]
impl Bls12381VerifyingKey {
    #[uniffi::constructor]
    pub fn new(public_key: &Bls12381PublicKey) -> Result<Self> {
        Ok(iota_crypto::bls12381::Bls12381VerifyingKey::new(&public_key.0).map(Self)?)
    }

    pub fn public_key(&self) -> Bls12381PublicKey {
        self.0.public_key().into()
    }

    pub fn verify(&self, message: &[u8], signature: &Bls12381Signature) -> Result<()> {
        Ok(
            iota_crypto::Verifier::<iota_types::Bls12381Signature>::verify(
                &self.0,
                message,
                &signature.0,
            )?,
        )
    }
}

#[derive(derive_more::From, uniffi::Object)]
pub struct ValidatorCommitteeSignatureVerifier(
    pub iota_crypto::bls12381::ValidatorCommitteeSignatureVerifier,
);

#[uniffi::export]
impl ValidatorCommitteeSignatureVerifier {
    #[uniffi::constructor]
    pub fn new(committee: ValidatorCommittee) -> Result<Self> {
        Ok(Self(
            iota_crypto::bls12381::ValidatorCommitteeSignatureVerifier::new(committee.into())?,
        ))
    }

    pub fn committee(&self) -> ValidatorCommittee {
        self.0.committee().clone().into()
    }

    pub fn verify_checkpoint_summary(
        &self,
        summary: &CheckpointSummary,
        signature: &ValidatorAggregatedSignature,
    ) -> Result<()> {
        Ok(self.0.verify_checkpoint_summary(&summary.0, &signature.0)?)
    }

    pub fn verify(&self, message: &[u8], signature: &ValidatorSignature) -> Result<()> {
        Ok(
            iota_crypto::Verifier::<iota_types::ValidatorSignature>::verify(
                &self.0,
                message,
                &signature.0,
            )?,
        )
    }

    pub fn verify_aggregated(
        &self,
        message: &[u8],
        signature: &ValidatorAggregatedSignature,
    ) -> Result<()> {
        Ok(iota_crypto::Verifier::<
            iota_types::ValidatorAggregatedSignature,
        >::verify(&self.0, message, &signature.0)?)
    }
}

#[derive(derive_more::From, uniffi::Object)]
pub struct ValidatorCommitteeSignatureAggregator(
    pub RwLock<iota_crypto::bls12381::ValidatorCommitteeSignatureAggregator>,
);

#[uniffi::export]
impl ValidatorCommitteeSignatureAggregator {
    #[uniffi::constructor]
    pub fn new_checkpoint_summary(
        committee: ValidatorCommittee,
        summary: &CheckpointSummary,
    ) -> Result<Self> {
        Ok(Self(
            iota_crypto::bls12381::ValidatorCommitteeSignatureAggregator::new_checkpoint_summary(
                committee.into(),
                &summary.0,
            )?
            .into(),
        ))
    }

    pub fn committee(&self) -> ValidatorCommittee {
        self.0
            .read()
            .expect("failed to read validator committee signature aggregator")
            .committee()
            .clone()
            .into()
    }

    pub fn add_signature(&self, signature: &ValidatorSignature) -> Result<()> {
        Ok(self
            .0
            .write()
            .expect("failed to read validator committee signature aggregator")
            .add_signature(signature.0.clone())?)
    }

    pub fn finish(&self) -> Result<ValidatorAggregatedSignature> {
        Ok(self
            .0
            .read()
            .expect("failed to read validator committee signature aggregator")
            .finish()?
            .into())
    }
}
