// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::types::{
    digest::{
        CheckpointContentsDigest, CheckpointDigest, Digest, TransactionDigest,
        TransactionEffectsDigest,
    },
    gas::GasCostSummary,
    signature::UserSignature,
    validator::{ValidatorAggregatedSignature, ValidatorCommitteeMember},
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
///                      digest                         ; contents_digest
///                      (option digest)                ; previous_digest
///                      gas-cost-summary               ; epoch_rolling_gas_cost_summary
///                      u64                            ; timestamp_ms
///                      (vector checkpoint-commitment) ; checkpoint_commitments
///                      (option end-of-epoch-data)     ; end_of_epoch_data
///                      bytes                          ; version_specific_data
/// ```
#[derive(derive_more::From, uniffi::Object)]
pub struct CheckpointSummary(pub iota_sdk::types::CheckpointSummary);

#[uniffi::export]
impl CheckpointSummary {
    #[uniffi::constructor]
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        epoch: EpochId,
        sequence_number: CheckpointSequenceNumber,
        network_total_transactions: u64,
        contents_digest: &CheckpointContentsDigest,
        previous_digest: Option<Arc<CheckpointDigest>>,
        epoch_rolling_gas_cost_summary: GasCostSummary,
        timestamp_ms: CheckpointTimestamp,
        checkpoint_commitments: Vec<Arc<CheckpointCommitment>>,
        end_of_epoch_data: Option<EndOfEpochData>,
        version_specific_data: Vec<u8>,
    ) -> Self {
        Self(iota_sdk::types::CheckpointSummary::new(
            epoch,
            sequence_number,
            network_total_transactions,
            **contents_digest,
            previous_digest.map(|v| **v),
            epoch_rolling_gas_cost_summary.into(),
            timestamp_ms,
            checkpoint_commitments
                .into_iter()
                .map(|v| v.0.clone())
                .collect(),
            end_of_epoch_data.map(Into::into),
            version_specific_data,
        ))
    }

    /// Epoch that this checkpoint belongs to.
    pub fn epoch(&self) -> u64 {
        self.0.epoch
    }

    /// The height of this checkpoint.
    pub fn sequence_number(&self) -> u64 {
        self.0.sequence_number
    }

    /// Total number of transactions committed since genesis, including those in
    /// this checkpoint.
    pub fn network_total_transactions(&self) -> u64 {
        self.0.network_total_transactions
    }

    /// The hash of the `CheckpointContents` for this checkpoint.
    pub fn contents_digest(&self) -> CheckpointContentsDigest {
        self.0.contents_digest.into()
    }

    /// The hash of the previous `CheckpointSummary`.
    ///
    /// This will be only be `None` for the first, or genesis checkpoint.
    pub fn previous_digest(&self) -> Option<Arc<CheckpointDigest>> {
        self.0.previous_digest.map(Into::into).map(Arc::new)
    }

    /// The running total gas costs of all transactions included in the current
    /// epoch so far until this checkpoint.
    pub fn epoch_rolling_gas_cost_summary(&self) -> GasCostSummary {
        self.0.epoch_rolling_gas_cost_summary.clone().into()
    }

    /// Timestamp of the checkpoint - number of milliseconds from the Unix epoch
    /// Checkpoint timestamps are monotonic, but not strongly monotonic -
    /// subsequent checkpoints can have same timestamp if they originate
    /// from the same underlining consensus commit
    pub fn timestamp_ms(&self) -> u64 {
        self.0.timestamp_ms
    }

    /// Commitments to checkpoint-specific state.
    pub fn checkpoint_commitments(&self) -> Vec<Arc<CheckpointCommitment>> {
        self.0
            .checkpoint_commitments
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }

    /// Extra data only present in the final checkpoint of an epoch.
    pub fn end_of_epoch_data(&self) -> Option<EndOfEpochData> {
        self.0.end_of_epoch_data.clone().map(Into::into)
    }

    /// CheckpointSummary is not an evolvable structure - it must be readable by
    /// any version of the code. Therefore, in order to allow extensions to
    /// be added to CheckpointSummary, we allow opaque data to be added to
    /// checkpoints which can be deserialized based on the current
    /// protocol version.
    pub fn version_specific_data(&self) -> Vec<u8> {
        self.0.version_specific_data.clone()
    }

    pub fn digest(&self) -> CheckpointDigest {
        self.0.digest().into()
    }

    pub fn signing_message(&self) -> Vec<u8> {
        self.0.signing_message()
    }

    pub fn signing_message_hex(&self) -> String {
        self.0.signing_message_hex()
    }
}

/// A [`CheckpointSummary`] together with an aggregated signature certifying it
/// under its epoch's validator committee.
#[derive(derive_more::From, uniffi::Object)]
pub struct SignedCheckpointSummary(pub iota_sdk::types::SignedCheckpointSummary);

#[uniffi::export]
impl SignedCheckpointSummary {
    #[uniffi::constructor]
    pub fn new(checkpoint: &CheckpointSummary, signature: &ValidatorAggregatedSignature) -> Self {
        Self(iota_sdk::types::SignedCheckpointSummary {
            checkpoint: checkpoint.0.clone(),
            signature: signature.0.clone(),
        })
    }

    pub fn checkpoint(&self) -> CheckpointSummary {
        self.0.checkpoint.clone().into()
    }

    pub fn signature(&self) -> ValidatorAggregatedSignature {
        self.0.signature.clone().into()
    }
}

/// The committed to contents of a checkpoint.
///
/// `CheckpointContents` contains a list of digests of Transactions, their
/// effects, and the user signatures that authorized their execution included in
/// a checkpoint.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// checkpoint-contents = %d00 checkpoint-contents-v1 ; variant 0
/// ```
#[derive(derive_more::From, uniffi::Object)]
pub struct CheckpointContents(pub iota_sdk::types::CheckpointContents);

#[uniffi::export]
impl CheckpointContents {
    #[uniffi::constructor]
    pub fn new_v1(contents: &CheckpointContentsV1) -> Self {
        Self(iota_sdk::types::CheckpointContents::new_v1(
            contents.0.clone(),
        ))
    }

    pub fn is_v1(&self) -> bool {
        self.0.is_v1()
    }

    pub fn as_v1(&self) -> CheckpointContentsV1 {
        self.0.as_v1().clone().into()
    }

    pub fn transactions(&self) -> Vec<Arc<CheckpointTransactionInfo>> {
        self.0
            .transactions()
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }

    pub fn digest(&self) -> CheckpointContentsDigest {
        self.0.digest().into()
    }

    /// The number of transactions in this checkpoint.
    pub fn len(&self) -> u64 {
        self.0.len() as _
    }

    /// Whether this checkpoint has no transactions.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// CheckpointContents are the transactions included in an upcoming checkpoint.
/// They must have already been causally ordered. Since the causal order
/// algorithm is the same among validators, we expect all honest validators to
/// come up with the same order for each checkpoint content.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// checkpoint-contents-v1 = (vector execution-digests)      ; transaction and effect digests
///                          (vector (vector user-signature)) ; set of user signatures for each
///                                                           ; transaction. MUST be the same
///                                                           ; length as the vector of digests
///
/// execution-digests = transaction-digest transaction-effects-digest   ; transaction, effects
/// ```
#[derive(derive_more::From, uniffi::Object)]
pub struct CheckpointContentsV1(pub iota_sdk::types::CheckpointContentsV1);

#[uniffi::export]
impl CheckpointContentsV1 {
    #[uniffi::constructor]
    pub fn new(transaction_info: Vec<Arc<CheckpointTransactionInfo>>) -> Self {
        Self(iota_sdk::types::CheckpointContentsV1::new(
            transaction_info.into_iter().map(|v| v.0.clone()).collect(),
        ))
    }

    pub fn transactions(&self) -> Vec<Arc<CheckpointTransactionInfo>> {
        self.0
            .transactions()
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }

    /// The number of transactions in this checkpoint.
    pub fn len(&self) -> u64 {
        self.0.len() as _
    }

    /// Whether this checkpoint has no transactions.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Transaction information committed to in a checkpoint
#[derive(derive_more::From, uniffi::Object)]
pub struct CheckpointTransactionInfo(pub iota_sdk::types::CheckpointTransactionInfo);

#[uniffi::export]
impl CheckpointTransactionInfo {
    #[uniffi::constructor]
    pub fn new(
        transaction: &TransactionDigest,
        effects: &TransactionEffectsDigest,
        signatures: Vec<Arc<UserSignature>>,
    ) -> Self {
        Self(iota_sdk::types::CheckpointTransactionInfo {
            transaction: **transaction,
            effects: **effects,
            signatures: signatures.into_iter().map(|v| v.0.clone()).collect(),
        })
    }

    pub fn transaction(&self) -> TransactionDigest {
        self.0.transaction.into()
    }

    pub fn effects(&self) -> TransactionEffectsDigest {
        self.0.effects.into()
    }

    pub fn signatures(&self) -> Vec<Arc<UserSignature>> {
        self.0
            .signatures
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
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
/// ecmh-live-object-set = %d00 digest
/// ```
#[derive(derive_more::From, uniffi::Object)]
pub struct CheckpointCommitment(pub iota_sdk::types::CheckpointCommitment);

#[uniffi::export]
impl CheckpointCommitment {
    pub fn is_ecmh_live_object_set(&self) -> bool {
        self.0.is_ecmh_live_object_set()
    }

    pub fn as_ecmh_live_object_set_digest(&self) -> Digest {
        self.0.as_ecmh_live_object_set_digest().into()
    }
}

/// Data which, when included in a [`CheckpointSummary`], signals the end of an
/// `Epoch`.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// end-of-epoch-data = (vector validator-committee-member) ; next_epoch_committee
///                     u64                                 ; next_epoch_protocol_version
///                     (vector checkpoint-commitment)      ; epoch_commitments
///                     i64                                 ; epoch_supply_change
/// ```
#[derive(Clone, uniffi::Record)]
pub struct EndOfEpochData {
    pub next_epoch_committee: Vec<ValidatorCommitteeMember>,
    pub next_epoch_protocol_version: u64,
    pub epoch_commitments: Vec<Arc<CheckpointCommitment>>,
    pub epoch_supply_change: i64,
}

impl From<iota_sdk::types::EndOfEpochData> for EndOfEpochData {
    fn from(value: iota_sdk::types::EndOfEpochData) -> Self {
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

impl From<EndOfEpochData> for iota_sdk::types::EndOfEpochData {
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

crate::export_iota_types_bcs_conversion!(EndOfEpochData);
crate::export_iota_types_objects_bcs_conversion!(
    CheckpointSummary,
    SignedCheckpointSummary,
    CheckpointContents,
    CheckpointContentsV1,
    CheckpointTransactionInfo,
    CheckpointCommitment
);
crate::export_iota_types_json_conversion!(EndOfEpochData);
crate::export_iota_types_objects_json_conversion!(
    CheckpointSummary,
    SignedCheckpointSummary,
    CheckpointContents,
    CheckpointContentsV1,
    CheckpointTransactionInfo,
    CheckpointCommitment
);
crate::export_iota_types_display!(EndOfEpochData);
crate::export_iota_types_objects_display!(
    CheckpointSummary,
    SignedCheckpointSummary,
    CheckpointContents,
    CheckpointContentsV1,
    CheckpointTransactionInfo,
    CheckpointCommitment
);
