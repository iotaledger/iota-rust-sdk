// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{
    CheckpointContentsDigest, CheckpointDigest, Digest, GasCostSummary, Object, SignedTransaction,
    TransactionDigest, TransactionEffects, TransactionEffectsDigest, TransactionEvents,
    UserSignature, ValidatorAggregatedSignature, ValidatorCommitteeMember,
};

pub type CheckpointSequenceNumber = u64;
pub type CheckpointTimestamp = u64;
pub type EpochId = u64;
pub type StakeUnit = u64;
pub type ProtocolVersion = u64;

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
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
#[non_exhaustive]
pub enum CheckpointCommitment {
    /// An Elliptic Curve Multiset Hash attesting to the set of Objects that
    /// compose the live state of the IOTA blockchain.
    EcmhLiveObjectSet { digest: Digest },
    // Other commitment types (e.g. merkle roots) go here.
}

impl CheckpointCommitment {
    crate::def_is!(EcmhLiveObjectSet);

    pub fn as_ecmh_live_object_set_digest(&self) -> Digest {
        let Self::EcmhLiveObjectSet { digest } = self;
        *digest
    }
}

impl std::fmt::Display for CheckpointCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckpointCommitment::EcmhLiveObjectSet { digest } => {
                write!(f, "EcmhLiveObjectSet({digest})")
            }
        }
    }
}

/// Data, which when included in a [`CheckpointSummary`], signals the end of an
/// `Epoch`.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// end-of-epoch-data = (vector validator-committee-member)   ; next-epoch-committee
///                     u64                                   ; next-epoch-protocol-version
///                     (vector checkpoint-commitment)        ; epoch-commitments
///                     i64                                   ; epoch-supply-change
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
pub struct EndOfEpochData {
    /// The set of Validators that will be in the ValidatorCommittee for the
    /// next epoch.
    pub next_epoch_committee: Vec<ValidatorCommitteeMember>,
    /// The protocol version that is in effect during the next epoch.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "bcs-schema", bcs_schema(as_type = "u64"))]
    pub next_epoch_protocol_version: ProtocolVersion,
    /// Commitments to epoch specific state (e.g. live object set)
    pub epoch_commitments: Vec<CheckpointCommitment>,
    /// The number of tokens that were minted (if positive) or burnt (if
    /// negative) in this epoch.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    pub epoch_supply_change: i64,
}

impl crate::TreeDisplay for EndOfEpochData {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("End of Epoch Data")?;
        w.children("Next Epoch Committee", &self.next_epoch_committee, false)?;
        w.leaf(
            "Next Epoch Protocol Version",
            &self.next_epoch_protocol_version,
            false,
        )?;
        w.leaves("Epoch Commitments", &self.epoch_commitments, false)?;
        w.leaf("Epoch Supply Change", &self.epoch_supply_change, true)
    }
}

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
///                      checkpoint-contents-digest     ; contents_digest
///                      (option checkpoint-digest)     ; previous_digest
///                      gas-cost-summary               ; epoch_rolling_gas_cost_summary
///                      u64                            ; timestamp_ms
///                      (vector checkpoint-commitment) ; checkpoint_commitments
///                      (option end-of-epoch-data)     ; end_of_epoch_data
///                      bytes                          ; version_specific_data
/// ```
#[derive(Clone, derive_more::Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
pub struct CheckpointSummary {
    /// Epoch that this checkpoint belongs to.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "bcs-schema", bcs_schema(as_type = "u64"))]
    pub epoch: EpochId,
    /// The height of this checkpoint.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "bcs-schema", bcs_schema(as_type = "u64"))]
    pub sequence_number: CheckpointSequenceNumber,
    /// Total number of transactions committed since genesis, including those in
    /// this checkpoint.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    pub network_total_transactions: u64,
    /// The hash of the [`CheckpointContents`] for this checkpoint.
    pub contents_digest: CheckpointContentsDigest,
    /// The hash of the previous `CheckpointSummary`.
    ///
    /// This will be only be `None` for the first, or genesis checkpoint.
    #[cfg_attr(feature = "serde", serde(default))]
    pub previous_digest: Option<CheckpointDigest>,
    /// The running total gas costs of all transactions included in the current
    /// epoch so far until this checkpoint.
    pub epoch_rolling_gas_cost_summary: GasCostSummary,
    /// Timestamp of the checkpoint - number of milliseconds from the Unix epoch
    /// Checkpoint timestamps are monotonic, but not strongly monotonic -
    /// subsequent checkpoints can have same timestamp if they originate
    /// from the same underlining consensus commit
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "bcs-schema", bcs_schema(as_type = "u64"))]
    pub timestamp_ms: CheckpointTimestamp,
    /// Commitments to checkpoint-specific state.
    #[cfg_attr(feature = "serde", serde(default))]
    pub checkpoint_commitments: Vec<CheckpointCommitment>,
    /// Extra data only present in the final checkpoint of an epoch.
    #[cfg_attr(feature = "serde", serde(default))]
    pub end_of_epoch_data: Option<EndOfEpochData>,
    /// CheckpointSummary is not an evolvable structure - it must be readable by
    /// any version of the code. Therefore, in order to allow extensions to
    /// be added to CheckpointSummary, we allow opaque data to be added to
    /// checkpoints which can be deserialized based on the current
    /// protocol version.
    #[cfg_attr(
        feature = "serde",
        serde(default, with = "crate::_serde::ReadableBase64Encoded")
    )]
    #[debug(
        "{:?}",
        <base64ct::Base64 as base64ct::Encoding>::encode_string(version_specific_data)
    )]
    pub version_specific_data: Vec<u8>,
}

impl crate::TreeDisplay for CheckpointSummary {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Checkpoint Summary")?;
        w.leaf("Epoch", &self.epoch, false)?;
        w.leaf("Sequence Number", &self.sequence_number, false)?;
        w.leaf(
            "Network Total Transactions",
            &self.network_total_transactions,
            false,
        )?;
        w.leaf("Contents Digest", &self.contents_digest, false)?;
        w.option_leaf("Previous Digest", &self.previous_digest, false)?;
        w.child(
            "Epoch Rolling Gas Cost",
            &self.epoch_rolling_gas_cost_summary,
            false,
        )?;
        w.leaf("Timestamp (ms)", &self.timestamp_ms, false)?;
        w.leaves(
            "Checkpoint Commitments",
            &self.checkpoint_commitments,
            false,
        )?;
        w.option_child("End of Epoch Data", &self.end_of_epoch_data, true)
    }
}

impl CheckpointSummary {
    /// Construct a `CheckpointSummary` from its constituent parts.
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        epoch: EpochId,
        sequence_number: CheckpointSequenceNumber,
        network_total_transactions: u64,
        contents_digest: CheckpointContentsDigest,
        previous_digest: Option<CheckpointDigest>,
        epoch_rolling_gas_cost_summary: GasCostSummary,
        timestamp_ms: CheckpointTimestamp,
        checkpoint_commitments: Vec<CheckpointCommitment>,
        end_of_epoch_data: Option<EndOfEpochData>,
        version_specific_data: Vec<u8>,
    ) -> Self {
        Self {
            epoch,
            sequence_number,
            network_total_transactions,
            contents_digest,
            previous_digest,
            epoch_rolling_gas_cost_summary,
            timestamp_ms,
            checkpoint_commitments,
            end_of_epoch_data,
            version_specific_data,
        }
    }

    /// The epoch that this checkpoint belongs to.
    pub fn epoch(&self) -> EpochId {
        self.epoch
    }

    /// The height of this checkpoint.
    pub fn sequence_number(&self) -> CheckpointSequenceNumber {
        self.sequence_number
    }

    /// Total number of transactions committed since genesis, including those in
    /// this checkpoint.
    pub fn network_total_transactions(&self) -> u64 {
        self.network_total_transactions
    }

    /// The hash of the [`CheckpointContents`] for this checkpoint.
    pub fn contents_digest(&self) -> CheckpointContentsDigest {
        self.contents_digest
    }

    /// The hash of the previous `CheckpointSummary`, or `None` for the genesis
    /// checkpoint.
    pub fn previous_digest(&self) -> Option<CheckpointDigest> {
        self.previous_digest
    }

    /// The running total gas costs of all transactions included in the current
    /// epoch so far until this checkpoint.
    pub fn epoch_rolling_gas_cost_summary(&self) -> &GasCostSummary {
        &self.epoch_rolling_gas_cost_summary
    }

    /// Timestamp of the checkpoint, in milliseconds from the Unix epoch.
    pub fn timestamp_ms(&self) -> CheckpointTimestamp {
        self.timestamp_ms
    }

    /// Commitments to checkpoint-specific state.
    pub fn checkpoint_commitments(&self) -> &[CheckpointCommitment] {
        &self.checkpoint_commitments
    }

    /// Extra data present only in the final checkpoint of an epoch.
    pub fn end_of_epoch_data(&self) -> Option<&EndOfEpochData> {
        self.end_of_epoch_data.as_ref()
    }

    /// Opaque, protocol-version-specific data carried by the checkpoint.
    pub fn version_specific_data(&self) -> &[u8] {
        &self.version_specific_data
    }

    /// The validator committee that takes effect in the next epoch, present
    /// only on the final checkpoint of an epoch.
    pub fn next_epoch_committee(&self) -> Option<&[ValidatorCommitteeMember]> {
        self.end_of_epoch_data
            .as_ref()
            .map(|data| data.next_epoch_committee.as_slice())
    }

    /// Whether this is the final checkpoint of an epoch.
    pub fn is_last_checkpoint_of_epoch(&self) -> bool {
        self.end_of_epoch_data.is_some()
    }
}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
pub struct SignedCheckpointSummary {
    pub checkpoint: CheckpointSummary,
    pub signature: ValidatorAggregatedSignature,
}

impl crate::TreeDisplay for SignedCheckpointSummary {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Signed Checkpoint Summary")?;
        w.child("Checkpoint", &self.checkpoint, false)?;
        w.child("Signature", &self.signature, true)
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
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
#[non_exhaustive]
pub enum CheckpointContents {
    V1(CheckpointContentsV1),
}

impl CheckpointContents {
    pub fn new_v1(contents: CheckpointContentsV1) -> Self {
        Self::V1(contents)
    }

    crate::def_is_as_into_opt!(V1(CheckpointContentsV1));

    /// Returns a reference to the list of transactions in this checkpoint.
    pub fn transactions(&self) -> &[CheckpointTransactionInfo] {
        match self {
            CheckpointContents::V1(v1) => v1.transactions(),
        }
    }

    /// Consumes the `CheckpointContentsV1` and returns the list of
    /// transactions.
    pub fn into_transactions(self) -> Vec<CheckpointTransactionInfo> {
        match self {
            CheckpointContents::V1(v1) => v1.into_transactions(),
        }
    }

    /// The number of transactions in this checkpoint.
    pub fn len(&self) -> usize {
        match self {
            CheckpointContents::V1(v1) => v1.len(),
        }
    }

    /// Whether this checkpoint has no transactions.
    pub fn is_empty(&self) -> bool {
        match self {
            CheckpointContents::V1(v1) => v1.is_empty(),
        }
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
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct CheckpointContentsV1 {
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=2).lift()))]
    transactions: Vec<CheckpointTransactionInfo>,
}

impl CheckpointContentsV1 {
    pub fn new(transactions: Vec<CheckpointTransactionInfo>) -> Self {
        Self { transactions }
    }

    /// Returns a reference to the list of transactions in this checkpoint.
    pub fn transactions(&self) -> &[CheckpointTransactionInfo] {
        &self.transactions
    }

    /// Consumes the `CheckpointContentsV1` and returns the list of
    /// transactions.
    pub fn into_transactions(self) -> Vec<CheckpointTransactionInfo> {
        self.transactions
    }

    /// The number of transactions in this checkpoint.
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Whether this checkpoint has no transactions.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

impl crate::TreeDisplay for CheckpointContents {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.enum_name("Checkpoint Contents");
        match self {
            Self::V1(v1) => v1.fmt_tree(w),
        }
    }
}

impl crate::TreeDisplay for CheckpointContentsV1 {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Checkpoint Contents V1")?;
        w.children("Transactions", self.transactions(), true)
    }
}

/// Transaction information committed to in a checkpoint
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct CheckpointTransactionInfo {
    pub transaction: TransactionDigest,
    pub effects: TransactionEffectsDigest,
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=2).lift()))]
    pub signatures: Vec<UserSignature>,
}

impl crate::TreeDisplay for CheckpointTransactionInfo {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Checkpoint Transaction Info")?;
        w.leaf("Transaction", &self.transaction, false)?;
        w.leaf("Effects", &self.effects, false)?;
        w.children("Signatures", &self.signatures, true)
    }
}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
pub struct CheckpointData {
    pub checkpoint_summary: SignedCheckpointSummary,
    pub checkpoint_contents: CheckpointContents,
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=1).lift()))]
    pub transactions: Vec<CheckpointTransaction>,
}

impl crate::TreeDisplay for CheckpointData {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Checkpoint Data")?;
        w.child("Checkpoint Summary", &self.checkpoint_summary, false)?;
        w.child("Contents", &self.checkpoint_contents, false)?;
        w.children("Transactions", &self.transactions, true)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
pub struct CheckpointTransaction {
    /// The input Transaction
    #[cfg_attr(
        feature = "serde",
        serde(with = "::serde_with::As::<crate::_serde::SignedTransactionWithIntentMessage>")
    )]
    #[cfg_attr(
        feature = "bcs-schema",
        bcs_schema(as_type = "%d01 intent-signed-transaction")
    )]
    pub transaction: SignedTransaction,
    /// The effects produced by executing this transaction
    pub effects: TransactionEffects,
    /// The events, if any, emitted by this transaction during execution
    pub events: Option<TransactionEvents>,
    /// The state of all inputs to this transaction as they were prior to
    /// execution.
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=2).lift()))]
    pub input_objects: Vec<Object>,
    /// The state of all output objects created or mutated by this transaction.
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=2).lift()))]
    pub output_objects: Vec<Object>,
}

impl crate::TreeDisplay for CheckpointTransaction {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Checkpoint Transaction")?;
        w.child("Transaction", &self.transaction, false)?;
        w.child("Effects", &self.effects, false)?;
        w.option_child("Events", &self.events, false)?;
        w.children("Input Objects", &self.input_objects, false)?;
        w.children("Output Objects", &self.output_objects, true)
    }
}

crate::impl_tree_display!(
    EndOfEpochData,
    CheckpointSummary,
    SignedCheckpointSummary,
    CheckpointContents,
    CheckpointContentsV1,
    CheckpointTransactionInfo,
    CheckpointData,
    CheckpointTransaction
);

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for CheckpointContentsV1 {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            use serde::ser::{SerializeSeq, SerializeTuple};

            if serializer.is_human_readable() {
                serializer.serialize_newtype_struct("CheckpointContentsV1", &self.transactions)
            } else {
                #[derive(serde::Serialize)]
                struct Digests<'a> {
                    transaction: &'a TransactionDigest,
                    effects: &'a TransactionEffectsDigest,
                }

                struct DigestSeq<'a>(&'a CheckpointContentsV1);
                impl Serialize for DigestSeq<'_> {
                    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                    where
                        S: Serializer,
                    {
                        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
                        for txn in &self.0.transactions {
                            let digests = Digests {
                                transaction: &txn.transaction,
                                effects: &txn.effects,
                            };
                            seq.serialize_element(&digests)?;
                        }
                        seq.end()
                    }
                }

                struct SignatureSeq<'a>(&'a CheckpointContentsV1);
                impl Serialize for SignatureSeq<'_> {
                    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                    where
                        S: Serializer,
                    {
                        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
                        for txn in &self.0.transactions {
                            seq.serialize_element(&txn.signatures)?;
                        }
                        seq.end()
                    }
                }

                let mut s = serializer.serialize_tuple(2)?;
                s.serialize_element(&DigestSeq(self))?;
                s.serialize_element(&SignatureSeq(self))?;
                s.end()
            }
        }
    }

    #[derive(serde::Deserialize)]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    struct ExecutionDigests {
        transaction: TransactionDigest,
        effects: TransactionEffectsDigest,
    }

    #[derive(serde::Deserialize)]
    #[cfg_attr(
        feature = "bcs-schema",
        derive(iota_bcs_schema::BcsSchema),
        bcs_schema(name = "checkpoint-contents-v1")
    )]
    struct BinaryContentsV1 {
        digests: Vec<ExecutionDigests>,
        signatures: Vec<Vec<UserSignature>>,
    }

    impl<'de> Deserialize<'de> for CheckpointContentsV1 {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let transactions: Vec<CheckpointTransactionInfo> =
                    Deserialize::deserialize(deserializer)?;
                Ok(Self { transactions })
            } else {
                let BinaryContentsV1 {
                    digests,
                    signatures,
                } = Deserialize::deserialize(deserializer)?;

                if digests.len() != signatures.len() {
                    return Err(serde::de::Error::custom(
                        "must have same number of signatures as transactions",
                    ));
                }

                Ok(Self {
                    transactions: digests
                        .into_iter()
                        .zip(signatures)
                        .map(
                            |(
                                ExecutionDigests {
                                    transaction,
                                    effects,
                                },
                                signatures,
                            )| CheckpointTransactionInfo {
                                transaction,
                                effects,
                                signatures,
                            },
                        )
                        .collect(),
                })
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use base64ct::{Base64, Encoding};
        #[cfg(target_arch = "wasm32")]
        use wasm_bindgen_test::wasm_bindgen_test as test;

        use super::*;

        #[test]
        fn signed_checkpoint_fixture() {
            // Checkpoint summaries created from a local network (iota start command)
            // http://localhost:9000/api/v1/checkpoints to see the list of checkpoints
            // To get the data of checkpoint 1 as base64, use:
            // curl -s http://localhost:9000/api/v1/checkpoints/1 -H "Accept: application/bcs" | base64
            const FIXTURES: &[&str] = &[
                "AAAAAAAAAAABAAAAAAAAAAIAAAAAAAAAIBqk0HxZmh1Bym2oL/3TlEnvb0FZbMJ594JGx2ZX9w2oASBCLJ9nhRE2EUG3C/XMPTdJTbK/1GjM585faUsOUQhFYgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC9f941lwEAAAAAAgAAAAAAAAAAAACx8KVNWdScdFfM3RDAC41byY37f2pdIhrjGI8SQVY7Vel7TCBQ/kvuRdINIrazvwgUOjAAAAEAAAAAAAEAEAAAAAAAAQA=",
                "DQAAAAAAAAB4DgAAAAAAAEo/AAAAAAAAIGJzt6qiBfbQHQufWpLivtr60pLRjm9dy7ulx34XrVVTASCV+2EoRe+2oCMWuVWVtl3ZIEdyaJgPhs+mCXiNtq6YygAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADyWus1lwEAAAABAmCNz/bRVQQKZW9IGbExEbUsV0aoa6cvOV+6/i7DhH0egUDmJKdR/fa18gULxyBc+dMABMkLDHQK/9Mmzmc8wrI6LSTVPir+sobfxmj9QGAInW0rF7eZ3Tb5DTMuVKejONSIEwAAAAAAAGCZ8l72H4AyuRRjZGCYLFzG8TTvHdrnZlfyy/7B6/yNCXN0CA32/PDcuLxLDY4K9dgOu/8rTFmfVPQtYxLfwxQnYHjBzDR+u77FGYviWFE/OGuTDQLCdJqAPiMwlV69GhCIEwAAAAAAAAkAAAAAAAAAAQAgIeRTzjDpjnTS3fkN3QCskISnmr5Z49j8JKFBGGuQjcAA8IoalbkCAAoAAWsAAAAAAAAADQAAAAAAAAC4F4HnXo6T6kpusCM8Gm7uXzE44DhcL0Faldy/mECSwlxBrcy4taqwhCdfgWVMmAsUOjAAAAEAAAAAAAEAEAAAAAAAAQA=",
            ];

            for fixture in FIXTURES {
                let bcs = Base64::decode_vec(fixture).unwrap();

                let checkpoint: SignedCheckpointSummary = bcs::from_bytes(&bcs).unwrap();
                let bytes = bcs::to_bytes(&checkpoint).unwrap();
                assert_eq!(bcs, bytes);
                let json = serde_json::to_string_pretty(&checkpoint).unwrap();
                println!("{json}");
            }
        }

        #[test]
        fn contents_fixture() {
            let fixture = "AAEgp6oAB8Qadn8+FqtdqeDIp8ViQNOZpMKs44MN0N5y7zIgqn5dKR1+8poL0pLNwRo/2knMnodwMTEDhqYL03kdewQBAWEAgpORkfH6ewjfFQYZJhmjkYq0/B3Set4mLJX/G0wUPb/V4H41gJipYu4I6ToyixnEuPQWxHKLckhNn+0UmI+pAJ9GegzEh0q2HWABmFMpFoPw0229dCfzWNOhHW5bes4H";

            let bcs = Base64::decode_vec(fixture).unwrap();

            let contents: CheckpointContents = bcs::from_bytes(&bcs).unwrap();
            let bytes = bcs::to_bytes(&contents).unwrap();
            assert_eq!(bcs, bytes);
            let json = serde_json::to_string_pretty(&contents).unwrap();
            println!("{json}");
        }
    }
}
