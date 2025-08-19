// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_types::GasCostSummary;

use crate::types::{
    crypto::validator::ValidatorCommitteeMember,
    digest::{CheckpointContentsDigest, CheckpointDigest, Digest},
};

pub type CheckpointSequenceNumber = u64;
pub type CheckpointTimestamp = u64;
pub type EpochId = u64;
pub type StakeUnit = u64;
pub type ProtocolVersion = u64;

/// A header for a Checkpoint on the IOTA blockchain.
///
/// On the IOTA network, checkpoints define the history of the blockchain. They
/// are quite similar to the concept of blocks used by other blockchains like
/// Bitcoin or Ethereum. The IOTA blockchain, however, forms checkpoints after
/// transaction execution has already happened to provide a certified history of
/// the chain, instead of being formed before execution.
///
/// Checkpoints commit to a variety of state including but not limited to:
/// - The hash of the previous checkpoint.
/// - The set of transaction digests, their corresponding effects digests, as
///   well as the set of user signatures which authorized its execution.
/// - The object's produced by a transaction.
/// - The set of live objects that make up the current state of the chain.
/// - On epoch transitions, the next validator committee.
///
/// `CheckpointSummary`s themselves don't directly include all of the above
/// information but they are the top-level type by which all the above are
/// committed to transitively via cryptographic hashes included in the summary.
/// `CheckpointSummary`s are signed and certified by a quorum of the validator
/// committee in a given epoch in order to allow verification of the chain's
/// state.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// checkpoint-summary = u64                            ; epoch
///                      u64                            ; sequence_number
///                      u64                            ; network_total_transactions
///                      digest                         ; content_digest
///                      (option digest)                ; previous_digest
///                      gas-cost-summary               ; epoch_rolling_gas_cost_summary
///                      u64                            ; timestamp_ms
///                      (vector checkpoint-commitment) ; checkpoint_commitments
///                      (option end-of-epoch-data)     ; end_of_epoch_data
///                      bytes                          ; version_specific_data
/// ```
#[derive(Clone, Debug, uniffi::Record)]
pub struct CheckpointSummary {
    /// Epoch that this checkpoint belongs to.
    pub epoch: u64,
    /// The height of this checkpoint.
    pub sequence_number: u64,
    /// Total number of transactions committed since genesis, including those in
    /// this checkpoint.
    pub network_total_transactions: u64,
    /// The hash of the `CheckpointContents` for this checkpoint.
    pub content_digest: Arc<CheckpointContentsDigest>,
    /// The hash of the previous `CheckpointSummary`.
    ///
    /// This will be only be `None` for the first, or genesis checkpoint.
    pub previous_digest: Option<Arc<CheckpointDigest>>,
    /// The running total gas costs of all transactions included in the current
    /// epoch so far until this checkpoint.
    pub epoch_rolling_gas_cost_summary: GasCostSummary,
    /// Timestamp of the checkpoint - number of milliseconds from the Unix epoch
    /// Checkpoint timestamps are monotonic, but not strongly monotonic -
    /// subsequent checkpoints can have same timestamp if they originate
    /// from the same underlining consensus commit
    pub timestamp_ms: u64,
    /// Commitments to checkpoint-specific state.
    pub checkpoint_commitments: Vec<Arc<CheckpointCommitment>>,
    /// Extra data only present in the final checkpoint of an epoch.
    pub end_of_epoch_data: Option<EndOfEpochData>,
    /// CheckpointSummary is not an evolvable structure - it must be readable by
    /// any version of the code. Therefore, in order to allow extensions to
    /// be added to CheckpointSummary, we allow opaque data to be added to
    /// checkpoints which can be deserialized based on the current
    /// protocol version.
    pub version_specific_data: Vec<u8>,
}

impl From<iota_types::CheckpointSummary> for CheckpointSummary {
    fn from(value: iota_types::CheckpointSummary) -> Self {
        Self {
            epoch: value.epoch,
            sequence_number: value.sequence_number,
            network_total_transactions: value.network_total_transactions,
            content_digest: Arc::new(value.content_digest.into()),
            previous_digest: value.previous_digest.map(Into::into).map(Arc::new),
            epoch_rolling_gas_cost_summary: value.epoch_rolling_gas_cost_summary,
            timestamp_ms: value.timestamp_ms,
            checkpoint_commitments: value
                .checkpoint_commitments
                .into_iter()
                .map(Into::into)
                .map(Arc::new)
                .collect(),
            end_of_epoch_data: value.end_of_epoch_data.map(Into::into),
            version_specific_data: value.version_specific_data,
        }
    }
}

impl From<CheckpointSummary> for iota_types::CheckpointSummary {
    fn from(value: CheckpointSummary) -> Self {
        Self {
            epoch: value.epoch,
            sequence_number: value.sequence_number,
            network_total_transactions: value.network_total_transactions,
            content_digest: **value.content_digest,
            previous_digest: value.previous_digest.map(|v| **v),
            epoch_rolling_gas_cost_summary: value.epoch_rolling_gas_cost_summary,
            timestamp_ms: value.timestamp_ms,
            checkpoint_commitments: value
                .checkpoint_commitments
                .into_iter()
                .map(|v| v.0.clone())
                .collect(),
            end_of_epoch_data: value.end_of_epoch_data.map(Into::into),
            version_specific_data: value.version_specific_data,
        }
    }
}

/// A commitment made by a checkpoint.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// ; CheckpointCommitment is an enum and each variant is prefixed with its index
/// checkpoint-commitment = ecmh-live-object-set
/// ecmh-live-object-set = %x00 digest
/// ```
#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct CheckpointCommitment(pub iota_types::CheckpointCommitment);

#[uniffi::export]
impl CheckpointCommitment {
    pub fn is_ecmh_live_object_set(&self) -> bool {
        self.0.is_ecmh_live_object_set()
    }

    pub fn as_ecmh_live_object_set_digest(&self) -> Digest {
        self.0.as_ecmh_live_object_set_digest().into()
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct EndOfEpochData {
    pub next_epoch_committee: Vec<ValidatorCommitteeMember>,
    pub next_epoch_protocol_version: u64,
    pub epoch_commitments: Vec<Arc<CheckpointCommitment>>,
    pub epoch_supply_change: i64,
}

impl From<iota_types::EndOfEpochData> for EndOfEpochData {
    fn from(value: iota_types::EndOfEpochData) -> Self {
        Self {
            next_epoch_committee: value
                .next_epoch_committee
                .into_iter()
                .map(Into::into)
                .collect(),
            next_epoch_protocol_version: value.next_epoch_protocol_version,
            epoch_commitments: value
                .epoch_commitments
                .into_iter()
                .map(Into::into)
                .map(Arc::new)
                .collect(),
            epoch_supply_change: value.epoch_supply_change,
        }
    }
}

impl From<EndOfEpochData> for iota_types::EndOfEpochData {
    fn from(value: EndOfEpochData) -> Self {
        Self {
            next_epoch_committee: value
                .next_epoch_committee
                .into_iter()
                .map(Into::into)
                .collect(),
            next_epoch_protocol_version: value.next_epoch_protocol_version,
            epoch_commitments: value
                .epoch_commitments
                .into_iter()
                .map(|v| v.0.clone())
                .collect(),
            epoch_supply_change: value.epoch_supply_change,
        }
    }
}
