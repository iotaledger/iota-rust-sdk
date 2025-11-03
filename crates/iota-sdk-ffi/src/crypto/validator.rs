// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::RwLock;

use crate::{
    error::Result,
    types::{
        checkpoint::CheckpointSummary,
        validator::{ValidatorAggregatedSignature, ValidatorCommittee, ValidatorSignature},
    },
};

#[derive(derive_more::From, uniffi::Object)]
pub struct ValidatorCommitteeSignatureVerifier(
    pub iota_sdk::crypto::validator::ValidatorCommitteeSignatureVerifier,
);

#[uniffi::export]
impl ValidatorCommitteeSignatureVerifier {
    #[uniffi::constructor]
    pub fn new(committee: ValidatorCommittee) -> Result<Self> {
        Ok(Self(
            iota_sdk::crypto::validator::ValidatorCommitteeSignatureVerifier::new(
                committee.into(),
            )?,
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
        Ok(iota_sdk::crypto::Verifier::<
            iota_sdk::types::ValidatorSignature,
        >::verify(&self.0, message, &signature.0)?)
    }

    pub fn verify_aggregated(
        &self,
        message: &[u8],
        signature: &ValidatorAggregatedSignature,
    ) -> Result<()> {
        Ok(iota_sdk::crypto::Verifier::<
            iota_sdk::types::ValidatorAggregatedSignature,
        >::verify(&self.0, message, &signature.0)?)
    }
}

#[derive(derive_more::From, uniffi::Object)]
pub struct ValidatorCommitteeSignatureAggregator(
    pub RwLock<iota_sdk::crypto::validator::ValidatorCommitteeSignatureAggregator>,
);

#[uniffi::export]
impl ValidatorCommitteeSignatureAggregator {
    #[uniffi::constructor]
    pub fn new_checkpoint_summary(
        committee: ValidatorCommittee,
        summary: &CheckpointSummary,
    ) -> Result<Self> {
        Ok(Self(
            iota_sdk::crypto::validator::ValidatorCommitteeSignatureAggregator::new_checkpoint_summary(
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
