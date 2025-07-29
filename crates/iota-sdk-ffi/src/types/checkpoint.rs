// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_types::GasCostSummary;

use crate::types::{
    crypto::ValidatorCommitteeMember,
    digest::{CheckpointContentsDigest, CheckpointDigest, Digest},
};

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct CheckpointSummary(pub iota_types::CheckpointSummary);

#[uniffi::export]
impl CheckpointSummary {
    pub fn epoch(&self) -> u64 {
        self.0.epoch
    }

    pub fn seq_number(&self) -> u64 {
        self.0.sequence_number
    }

    pub fn network_total_transactions(&self) -> u64 {
        self.0.network_total_transactions
    }

    pub fn content_digest(&self) -> CheckpointContentsDigest {
        self.0.content_digest.into()
    }

    pub fn previous_digest(&self) -> Option<Arc<CheckpointDigest>> {
        self.0.previous_digest.map(Into::into).map(Arc::new)
    }

    pub fn epoch_rolling_gas_cost_summary(&self) -> GasCostSummary {
        self.0.epoch_rolling_gas_cost_summary.clone()
    }

    pub fn timestamp_ms(&self) -> u64 {
        self.0.timestamp_ms
    }

    pub fn checkpoint_commitments(&self) -> Vec<Arc<CheckpointCommitment>> {
        self.0
            .checkpoint_commitments
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }

    pub fn end_of_epoch_data(&self) -> Option<Arc<EndOfEpochData>> {
        self.0
            .end_of_epoch_data
            .clone()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn version_specific_data(&self) -> Vec<u8> {
        self.0.version_specific_data.clone()
    }
}

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct CheckpointCommitment(pub iota_types::CheckpointCommitment);

#[uniffi::export]
impl CheckpointCommitment {
    pub fn is_ecmh_live_object_set(&self) -> bool {
        matches!(
            self.0,
            iota_types::CheckpointCommitment::EcmhLiveObjectSet { .. }
        )
    }

    pub fn as_ecmh_live_object_set_digest(&self) -> Digest {
        let iota_types::CheckpointCommitment::EcmhLiveObjectSet { digest } = self.0.clone();
        digest.into()
    }
}

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct EndOfEpochData(pub iota_types::EndOfEpochData);

#[uniffi::export]
impl EndOfEpochData {
    pub fn next_epoch_committee(&self) -> Vec<Arc<ValidatorCommitteeMember>> {
        self.0
            .next_epoch_committee
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }

    pub fn next_epoch_protocol_version(&self) -> u64 {
        self.0.next_epoch_protocol_version
    }

    pub fn epoch_commitments(&self) -> Vec<Arc<CheckpointCommitment>> {
        self.0
            .epoch_commitments
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }

    pub fn epoch_supply_change(&self) -> i64 {
        self.0.epoch_supply_change
    }
}
