// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_sdk::types::TransactionExpiration;

use crate::{
    error::Result,
    types::{
        address::Address,
        checkpoint::{CheckpointTimestamp, EpochId, ProtocolVersion},
        digest::{ConsensusCommitDigest, TransactionDigest, TransactionEffectsDigest},
        events::Event,
        move_core::{Identifier, TypeTag},
        object::{GenesisObject, ObjectId, ObjectReference},
        signature::UserSignature,
        transaction::v1::TransactionEffectsV1,
        version::Version,
    },
};

pub mod v1;

/// Transaction
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// transaction = %d00 transaction-v1
///
/// transaction-v1 = transaction-kind address gas-payment transaction-expiration
/// ```
#[derive(Clone, Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct Transaction(pub iota_sdk::types::Transaction);

#[uniffi::export]
impl Transaction {
    #[uniffi::constructor]
    pub fn new_v1(transaction_v1: &TransactionV1) -> Self {
        Self(iota_sdk::types::Transaction::V1(transaction_v1.0.clone()))
    }

    pub fn as_v1(&self) -> Arc<TransactionV1> {
        match &self.0 {
            iota_sdk::types::Transaction::V1(tx) => Arc::new(TransactionV1(tx.clone())),
            _ => unimplemented!("a new enum variant was added and needs to be handled"),
        }
    }

    pub fn kind(&self) -> TransactionKind {
        self.as_v1().kind()
    }

    pub fn sender(&self) -> Address {
        self.as_v1().sender()
    }

    pub fn gas_payment(&self) -> GasPayment {
        self.as_v1().gas_payment()
    }

    pub fn expiration(&self) -> TransactionExpiration {
        self.as_v1().expiration()
    }

    pub fn digest(&self) -> TransactionDigest {
        self.as_v1().digest()
    }

    /// Get the signing digest.
    pub fn signing_digest(&self) -> Vec<u8> {
        self.0.signing_digest().to_vec()
    }

    /// Get the signing digest as a hex string.
    pub fn signing_digest_hex(&self) -> String {
        self.0.signing_digest_hex()
    }

    /// Serialize the transaction as a base64-encoded string.
    pub fn to_base64(&self) -> String {
        self.0.to_base64()
    }

    /// Deserialize a transaction from a base64-encoded string.
    #[uniffi::constructor]
    pub fn from_base64(base64: String) -> Result<Self> {
        Ok(Transaction(iota_sdk::types::Transaction::from_base64(
            &base64,
        )?))
    }
}

/// A transaction
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// transaction = %d00 transaction-v1
///
/// transaction-v1 = transaction-kind address gas-payment transaction-expiration
/// ```
#[derive(Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct TransactionV1(pub iota_sdk::types::TransactionV1);

#[uniffi::export]
impl TransactionV1 {
    #[uniffi::constructor]
    pub fn new(
        kind: TransactionKind,
        sender: &Address,
        gas_payment: GasPayment,
        expiration: TransactionExpiration,
    ) -> Self {
        Self(iota_sdk::types::TransactionV1 {
            kind: kind.into(),
            sender: **sender,
            gas_payment: gas_payment.into(),
            expiration,
        })
    }

    pub fn kind(&self) -> TransactionKind {
        self.0.kind.clone().into()
    }

    pub fn sender(&self) -> Address {
        self.0.sender.into()
    }

    pub fn gas_payment(&self) -> GasPayment {
        self.0.gas_payment.clone().into()
    }

    pub fn expiration(&self) -> TransactionExpiration {
        self.0.expiration
    }

    pub fn digest(&self) -> TransactionDigest {
        self.0.digest().into()
    }

    /// Get the signing digest.
    pub fn signing_digest(&self) -> Vec<u8> {
        self.0.signing_digest().to_vec()
    }

    /// Get the signing digest as a hex string.
    pub fn signing_digest_hex(&self) -> String {
        self.0.signing_digest_hex()
    }

    /// Serialize the transaction as a base64-encoded string.
    pub fn to_base64(&self) -> String {
        self.0.to_base64()
    }

    /// Deserialize a transaction from a base64-encoded string.
    #[uniffi::constructor]
    pub fn from_base64(bytes: String) -> Result<Self> {
        Ok(Self(iota_sdk::types::TransactionV1::from_base64(&bytes)?))
    }
}

#[derive(Clone, uniffi::Record)]
pub struct SignedTransaction {
    pub transaction: Arc<Transaction>,
    pub signatures: Vec<Arc<UserSignature>>,
}

impl From<iota_sdk::types::SignedTransaction> for SignedTransaction {
    fn from(value: iota_sdk::types::SignedTransaction) -> Self {
        Self {
            transaction: Arc::new(Transaction(value.transaction)),
            signatures: value
                .signatures
                .into_iter()
                .map(Into::into)
                .map(Arc::new)
                .collect(),
        }
    }
}

impl From<SignedTransaction> for iota_sdk::types::SignedTransaction {
    fn from(value: SignedTransaction) -> Self {
        Self {
            transaction: value.transaction.0.clone(),
            signatures: value.signatures.into_iter().map(|v| v.0.clone()).collect(),
        }
    }
}

/// Transaction type
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// transaction-kind    =  %d00 programmable-transaction               ; Programmable
///                     =/ %d01 genesis-transaction                    ; Genesis
///                     =/ %d02 consensus-commit-prologue-v1           ; ConsensusCommitPrologueV1
///                     =/ %d03                                        ; AuthenticatorStateUpdateV1Deprecated
///                     =/ %d04 (vector end-of-epoch-transaction-kind) ; EndOfEpoch
///                     =/ %d05 randomness-state-update                ; RandomnessStateUpdate
///                     =/ %d06 transaction-deny-rules-update          ; TransactionDenyRulesUpdate
/// ```
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Enum)]
#[uniffi::export(Debug, Display, Eq, Hash)]
pub enum TransactionKind {
    /// A user transaction comprised of a series of native commands and move
    /// calls
    Programmable { tx: Arc<ProgrammableTransaction> },
    /// The genesis transaction
    Genesis { tx: Arc<GenesisTransaction> },
    /// V1 of the consensus commit prologue system transaction
    ConsensusCommitPrologueV1 { tx: Arc<ConsensusCommitPrologueV1> },
    /// A deprecated authenticator state update, retained so the BCS layout
    /// keeps its variant index
    AuthenticatorStateUpdateV1Deprecated,
    /// Set of operations run at the end of an epoch
    EndOfEpoch { txs: Vec<EndOfEpochTransactionKind> },
    /// Update the on-chain randomness state
    RandomnessStateUpdate { tx: RandomnessStateUpdate },
    /// Update the transaction deny rules
    TransactionDenyRulesUpdate { tx: TransactionDenyRulesUpdate },
}

impl From<iota_sdk::types::TransactionKind> for TransactionKind {
    fn from(value: iota_sdk::types::TransactionKind) -> Self {
        match value {
            iota_sdk::types::TransactionKind::Programmable(tx) => Self::Programmable {
                tx: Arc::new(tx.into()),
            },
            iota_sdk::types::TransactionKind::Genesis(tx) => Self::Genesis {
                tx: Arc::new(tx.into()),
            },
            iota_sdk::types::TransactionKind::ConsensusCommitPrologueV1(tx) => {
                Self::ConsensusCommitPrologueV1 {
                    tx: Arc::new(tx.into()),
                }
            }
            iota_sdk::types::TransactionKind::AuthenticatorStateUpdateV1Deprecated => {
                Self::AuthenticatorStateUpdateV1Deprecated
            }
            iota_sdk::types::TransactionKind::EndOfEpoch(txs) => Self::EndOfEpoch {
                txs: txs.into_iter().map(Into::into).collect(),
            },
            iota_sdk::types::TransactionKind::RandomnessStateUpdate(tx) => {
                Self::RandomnessStateUpdate { tx: tx.into() }
            }
            iota_sdk::types::TransactionKind::TransactionDenyRulesUpdate(tx) => {
                Self::TransactionDenyRulesUpdate { tx: tx.into() }
            }
            _ => unimplemented!("a new enum variant was added and needs to be handled"),
        }
    }
}

impl From<TransactionKind> for iota_sdk::types::TransactionKind {
    fn from(value: TransactionKind) -> Self {
        match value {
            TransactionKind::Programmable { tx } => Self::Programmable(tx.0.clone()),
            TransactionKind::Genesis { tx } => Self::Genesis(tx.0.clone()),
            TransactionKind::ConsensusCommitPrologueV1 { tx } => {
                Self::ConsensusCommitPrologueV1(tx.0.clone())
            }
            TransactionKind::AuthenticatorStateUpdateV1Deprecated => {
                Self::AuthenticatorStateUpdateV1Deprecated
            }
            TransactionKind::EndOfEpoch { txs } => {
                Self::EndOfEpoch(txs.into_iter().map(Into::into).collect())
            }
            TransactionKind::RandomnessStateUpdate { tx } => Self::RandomnessStateUpdate(tx.into()),
            TransactionKind::TransactionDenyRulesUpdate { tx } => {
                Self::TransactionDenyRulesUpdate(tx.into())
            }
        }
    }
}

impl std::fmt::Display for TransactionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&iota_sdk::types::TransactionKind::from(self.clone()), f)
    }
}

impl std::hash::Hash for TransactionKind {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        iota_sdk::types::TransactionKind::from(self.clone()).hash(state);
    }
}

/// A user transaction
///
/// Contains a series of native commands and move calls where the results of one
/// command can be used in future commands.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// ptb = (vector input) (vector command)
/// ```
#[derive(Debug, derive_more::Display, derive_more::From, Eq, Hash, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Display, Eq, Hash)]
pub struct ProgrammableTransaction(pub iota_sdk::types::ProgrammableTransaction);

#[uniffi::export]
impl ProgrammableTransaction {
    #[uniffi::constructor]
    pub fn new(inputs: Vec<Input>, commands: Vec<Command>) -> Self {
        Self(iota_sdk::types::ProgrammableTransaction {
            inputs: inputs.into_iter().map(Into::into).collect(),
            commands: commands.into_iter().map(Into::into).collect(),
        })
    }

    /// Input objects or primitive values
    pub fn inputs(&self) -> Vec<Input> {
        self.0.inputs.iter().cloned().map(Into::into).collect()
    }

    /// The commands to be executed sequentially. A failure in any command will
    /// result in the failure of the entire transaction.
    pub fn commands(&self) -> Vec<Command> {
        self.0.commands.iter().cloned().map(Into::into).collect()
    }
}

/// An input to a user transaction
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// input = call-arg
///
/// call-arg   =  %d00 bytes        ; Pure
///            =/ %d01 object-arg   ; Object
///
/// object-arg =  %d00 object-reference     ; ImmutableOrOwned
///            =/ %d01 object-id u64 bool   ; Shared
///            =/ %d02 object-reference     ; Receiving
/// ```
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Enum)]
#[uniffi::export(Debug, Eq)]
pub enum Input {
    /// A move value serialized as BCS
    Pure { value: Vec<u8> },
    /// A move object that is either immutable or address owned
    ImmutableOrOwned { object_ref: ObjectReference },
    /// A move object whose owner is "Shared"
    Shared {
        shared_object_ref: SharedObjectReference,
    },
    /// A move object that is being received
    Receiving { object_ref: ObjectReference },
}

impl From<iota_sdk::types::Input> for Input {
    fn from(value: iota_sdk::types::Input) -> Self {
        match value {
            iota_sdk::types::Input::Pure(value) => Self::Pure { value },
            iota_sdk::types::Input::ImmutableOrOwned(r) => Self::ImmutableOrOwned {
                object_ref: r.into(),
            },
            iota_sdk::types::Input::Shared(r) => Self::Shared {
                shared_object_ref: r.into(),
            },
            iota_sdk::types::Input::Receiving(r) => Self::Receiving {
                object_ref: r.into(),
            },
            _ => unimplemented!("a new enum variant was added and needs to be handled"),
        }
    }
}

impl From<Input> for iota_sdk::types::Input {
    fn from(value: Input) -> Self {
        match value {
            Input::Pure { value } => Self::Pure(value),
            Input::ImmutableOrOwned { object_ref } => Self::ImmutableOrOwned(object_ref.into()),
            Input::Shared { shared_object_ref } => Self::Shared(shared_object_ref.into()),
            Input::Receiving { object_ref } => Self::Receiving(object_ref.into()),
        }
    }
}

/// A single command in a programmable transaction.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// command =  command-move-call
///         =/ command-transfer-objects
///         =/ command-split-coins
///         =/ command-merge-coins
///         =/ command-publish
///         =/ command-make-move-vector
///         =/ command-upgrade
///
/// command-move-call           = %d00 move-call
/// command-transfer-objects    = %d01 transfer-objects
/// command-split-coins         = %d02 split-coins
/// command-merge-coins         = %d03 merge-coins
/// command-publish             = %d04 publish
/// command-make-move-vector    = %d05 make-move-vector
/// command-upgrade             = %d06 upgrade
/// ```
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Enum)]
#[uniffi::export(Debug, Eq)]
pub enum Command {
    /// A call to either an entry or a public Move function
    MoveCall { move_call: Arc<MoveCall> },
    /// It sends n-objects to the specified address. These objects must have
    /// store (public transfer) and either the previous owner must be an
    /// address or the object must be newly created.
    TransferObjects {
        transfer_objects: Arc<TransferObjects>,
    },
    /// It splits off some amounts into a new coins with those amounts
    SplitCoins { split_coins: Arc<SplitCoins> },
    /// It merges n-coins into the first coin
    MergeCoins { merge_coins: Arc<MergeCoins> },
    /// Publishes a Move package. It takes the package bytes and a list of the
    /// package's transitive dependencies to link against on-chain.
    Publish { publish: Arc<Publish> },
    /// Given n-values of the same type, it constructs a vector. For non objects
    /// or an empty vector, the type tag must be specified.
    MakeMoveVector {
        make_move_vector: Arc<MakeMoveVector>,
    },
    /// Upgrades a Move package
    Upgrade { upgrade: Arc<Upgrade> },
}

impl From<iota_sdk::types::Command> for Command {
    fn from(value: iota_sdk::types::Command) -> Self {
        match value {
            iota_sdk::types::Command::MoveCall(c) => Self::MoveCall {
                move_call: Arc::new(c.into()),
            },
            iota_sdk::types::Command::TransferObjects(c) => Self::TransferObjects {
                transfer_objects: Arc::new(c.into()),
            },
            iota_sdk::types::Command::SplitCoins(c) => Self::SplitCoins {
                split_coins: Arc::new(c.into()),
            },
            iota_sdk::types::Command::MergeCoins(c) => Self::MergeCoins {
                merge_coins: Arc::new(c.into()),
            },
            iota_sdk::types::Command::Publish(c) => Self::Publish {
                publish: Arc::new(c.into()),
            },
            iota_sdk::types::Command::MakeMoveVector(c) => Self::MakeMoveVector {
                make_move_vector: Arc::new(c.into()),
            },
            iota_sdk::types::Command::Upgrade(c) => Self::Upgrade {
                upgrade: Arc::new(c.into()),
            },
            _ => unimplemented!("a new enum variant was added and needs to be handled"),
        }
    }
}

impl From<Command> for iota_sdk::types::Command {
    fn from(value: Command) -> Self {
        match value {
            Command::MoveCall { move_call } => Self::MoveCall(move_call.0.clone()),
            Command::TransferObjects { transfer_objects } => {
                Self::TransferObjects(transfer_objects.0.clone())
            }
            Command::SplitCoins { split_coins } => Self::SplitCoins(split_coins.0.clone()),
            Command::MergeCoins { merge_coins } => Self::MergeCoins(merge_coins.0.clone()),
            Command::Publish { publish } => Self::Publish(publish.0.clone()),
            Command::MakeMoveVector { make_move_vector } => {
                Self::MakeMoveVector(make_move_vector.0.clone())
            }
            Command::Upgrade { upgrade } => Self::Upgrade(upgrade.0.clone()),
        }
    }
}

/// Command to transfer ownership of a set of objects to an address
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// transfer-objects = (vector argument) argument
/// ```
#[derive(Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct TransferObjects(pub iota_sdk::types::TransferObjects);

#[uniffi::export]
impl TransferObjects {
    #[uniffi::constructor]
    pub fn new(objects: Vec<Arc<Argument>>, address: Arc<Argument>) -> Self {
        Self(iota_sdk::types::TransferObjects {
            objects: objects.iter().map(|argument| argument.0).collect(),
            address: address.0,
        })
    }

    /// Set of objects to transfer
    pub fn objects(&self) -> Vec<Arc<Argument>> {
        self.0
            .objects
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }

    /// The address to transfer ownership to
    pub fn address(&self) -> Argument {
        self.0.address.into()
    }
}

/// Command to split a single coin object into multiple coins
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// split-coins = argument (vector argument)
/// ```
#[derive(Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct SplitCoins(pub iota_sdk::types::SplitCoins);

#[uniffi::export]
impl SplitCoins {
    #[uniffi::constructor]
    pub fn new(coin: &Argument, amounts: Vec<Arc<Argument>>) -> Self {
        Self(iota_sdk::types::SplitCoins {
            coin: coin.0,
            amounts: amounts.iter().map(|amount| amount.0).collect(),
        })
    }

    /// The coin to split
    pub fn coin(&self) -> Argument {
        self.0.coin.into()
    }

    /// The amounts to split off
    pub fn amounts(&self) -> Vec<Arc<Argument>> {
        self.0
            .amounts
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }
}

/// Command to merge multiple coins of the same type into a single coin
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// merge-coins = argument (vector argument)
/// ```
#[derive(Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct MergeCoins(pub iota_sdk::types::MergeCoins);

#[uniffi::export]
impl MergeCoins {
    #[uniffi::constructor]
    pub fn new(coin: &Argument, coins_to_merge: Vec<Arc<Argument>>) -> Self {
        Self(iota_sdk::types::MergeCoins {
            coin: coin.0,
            coins_to_merge: coins_to_merge.iter().map(|coin| coin.0).collect(),
        })
    }

    /// Coin to merge coins into
    pub fn coin(&self) -> Argument {
        self.0.coin.into()
    }

    /// Set of coins to merge into `coin`
    ///
    /// All listed coins must be of the same type and be the same type as `coin`
    pub fn coins_to_merge(&self) -> Vec<Arc<Argument>> {
        self.0
            .coins_to_merge
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }
}

/// Command to publish a new move package
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// publish = (vector bytes)        ; the serialized move modules
///           (vector object-id)    ; the set of package dependencies
/// ```
#[derive(Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct Publish(pub iota_sdk::types::Publish);

#[uniffi::export]
impl Publish {
    #[uniffi::constructor]
    pub fn new(modules: Vec<Vec<u8>>, dependencies: Vec<Arc<ObjectId>>) -> Self {
        Self(iota_sdk::types::Publish {
            modules,
            dependencies: dependencies.iter().map(|object_id| object_id.0).collect(),
        })
    }

    /// The serialized move modules
    pub fn modules(&self) -> Vec<Vec<u8>> {
        self.0.modules.clone()
    }

    /// Set of packages that the to-be published package depends on
    pub fn dependencies(&self) -> Vec<Arc<ObjectId>> {
        self.0
            .dependencies
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }
}

/// Command to build a move vector out of a set of individual elements
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// make-move-vector = (option type-tag) (vector argument)
/// ```
#[derive(Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct MakeMoveVector(pub iota_sdk::types::MakeMoveVector);

#[uniffi::export]
impl MakeMoveVector {
    #[uniffi::constructor]
    pub fn new(type_tag: Option<Arc<TypeTag>>, elements: Vec<Arc<Argument>>) -> Self {
        Self(iota_sdk::types::MakeMoveVector {
            type_tag: type_tag.map(|type_tag| type_tag.0.clone()),
            elements: elements.iter().map(|element| element.0).collect(),
        })
    }

    /// Type of the individual elements
    ///
    /// This is required to be set when the type can't be inferred, for example
    /// when the set of provided arguments are all pure input values.
    pub fn type_tag(&self) -> Option<Arc<TypeTag>> {
        self.0.type_tag.clone().map(Into::into).map(Arc::new)
    }

    /// The set individual elements to build the vector with
    pub fn elements(&self) -> Vec<Arc<Argument>> {
        self.0
            .elements
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }
}

/// Command to upgrade an already published package
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// upgrade = (vector bytes)        ; move modules
///           (vector object-id)    ; dependencies
///           object-id             ; package-id of the package
///           argument              ; upgrade ticket
/// ```
#[derive(Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct Upgrade(pub iota_sdk::types::Upgrade);

#[uniffi::export]
impl Upgrade {
    #[uniffi::constructor]
    pub fn new(
        modules: Vec<Vec<u8>>,
        dependencies: Vec<Arc<ObjectId>>,
        package: Arc<ObjectId>,
        ticket: Arc<Argument>,
    ) -> Self {
        Self(iota_sdk::types::Upgrade {
            modules,
            dependencies: dependencies.iter().map(|dependency| dependency.0).collect(),
            package: package.0,
            ticket: ticket.0,
        })
    }

    /// The serialized move modules
    pub fn modules(&self) -> Vec<Vec<u8>> {
        self.0.modules.clone()
    }

    /// Set of packages that the to-be published package depends on
    pub fn dependencies(&self) -> Vec<Arc<ObjectId>> {
        self.0
            .dependencies
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }

    /// Package id of the package to upgrade
    pub fn package(&self) -> ObjectId {
        self.0.package.into()
    }

    /// Ticket authorizing the upgrade
    pub fn ticket(&self) -> Argument {
        self.0.ticket.into()
    }
}

/// V1 of the consensus commit prologue system transaction
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// consensus-commit-prologue-v1 = u64 u64 (option u64) u64 digest
///                                consensus-determined-version-assignments
/// ```
#[derive(Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct ConsensusCommitPrologueV1(pub iota_sdk::types::ConsensusCommitPrologueV1);

#[uniffi::export]
impl ConsensusCommitPrologueV1 {
    #[uniffi::constructor]
    pub fn new(
        epoch: u64,
        round: u64,
        sub_dag_index: Option<u64>,
        commit_timestamp_ms: CheckpointTimestamp,
        consensus_commit_digest: &ConsensusCommitDigest,
        consensus_determined_version_assignments: &ConsensusDeterminedVersionAssignments,
    ) -> Self {
        Self(iota_sdk::types::ConsensusCommitPrologueV1 {
            epoch,
            round,
            sub_dag_index,
            commit_timestamp_ms,
            consensus_commit_digest: consensus_commit_digest.0,
            consensus_determined_version_assignments: consensus_determined_version_assignments
                .0
                .clone(),
        })
    }

    /// Epoch of the commit prologue transaction
    pub fn epoch(&self) -> u64 {
        self.0.epoch
    }

    /// Consensus round of the commit
    pub fn round(&self) -> u64 {
        self.0.round
    }

    /// The sub DAG index of the consensus commit. This field will be populated
    /// if there are multiple consensus commits per round.
    pub fn sub_dag_index(&self) -> Option<u64> {
        self.0.sub_dag_index
    }

    /// Unix timestamp from consensus
    pub fn commit_timestamp_ms(&self) -> CheckpointTimestamp {
        self.0.commit_timestamp_ms
    }

    /// Digest of consensus output
    pub fn consensus_commit_digest(&self) -> ConsensusCommitDigest {
        self.0.consensus_commit_digest.into()
    }

    /// Stores consensus handler determined shared object version assignments.
    pub fn consensus_determined_version_assignments(
        &self,
    ) -> ConsensusDeterminedVersionAssignments {
        self.0
            .consensus_determined_version_assignments
            .clone()
            .into()
    }
}

#[derive(Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct ConsensusDeterminedVersionAssignments(
    pub iota_sdk::types::ConsensusDeterminedVersionAssignments,
);

#[uniffi::export]
impl ConsensusDeterminedVersionAssignments {
    #[uniffi::constructor]
    pub fn new_canceled_transactions(canceled_transactions: Vec<Arc<CanceledTransaction>>) -> Self {
        Self(
            iota_sdk::types::ConsensusDeterminedVersionAssignments::CanceledTransactions {
                canceled_transactions: canceled_transactions
                    .into_iter()
                    .map(|v| v.0.clone())
                    .collect(),
            },
        )
    }

    pub fn is_canceled_transactions(&self) -> bool {
        self.0.is_canceled_transactions()
    }

    pub fn as_canceled_transactions(&self) -> Vec<Arc<CanceledTransaction>> {
        self.0
            .as_canceled_transactions()
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }
}

/// A transaction that was canceled
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// canceled-transaction = digest (vector version-assignment)
/// ```
#[derive(Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct CanceledTransaction(pub iota_sdk::types::CanceledTransaction);

#[uniffi::export]
impl CanceledTransaction {
    #[uniffi::constructor]
    pub fn new(
        digest: &TransactionDigest,
        version_assignments: Vec<Arc<VersionAssignment>>,
    ) -> Self {
        Self(iota_sdk::types::CanceledTransaction {
            digest: digest.0,
            version_assignments: version_assignments
                .into_iter()
                .map(|v| v.0.clone())
                .collect(),
        })
    }

    pub fn digest(&self) -> TransactionDigest {
        self.0.digest.into()
    }

    pub fn version_assignments(&self) -> Vec<Arc<VersionAssignment>> {
        self.0
            .version_assignments
            .clone()
            .into_iter()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }
}

/// Object version assignment from consensus
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// version-assignment = object-id u64
/// ```
#[derive(Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct VersionAssignment(iota_sdk::types::VersionAssignment);

#[uniffi::export]
impl VersionAssignment {
    #[uniffi::constructor]
    pub fn new(object_id: &ObjectId, version: &Version) -> Self {
        Self(iota_sdk::types::VersionAssignment {
            object_id: object_id.0,
            version: **version,
        })
    }

    pub fn object_id(&self) -> ObjectId {
        self.0.object_id.into()
    }

    pub fn version(&self) -> Version {
        self.0.version.into()
    }
}

/// The genesis transaction
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// genesis-transaction = (vector genesis-object)
/// ```
#[derive(Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct GenesisTransaction(iota_sdk::types::GenesisTransaction);

#[uniffi::export]
impl GenesisTransaction {
    #[uniffi::constructor]
    pub fn new(objects: Vec<Arc<GenesisObject>>, events: Vec<Event>) -> crate::error::Result<Self> {
        Ok(Self(iota_sdk::types::GenesisTransaction {
            objects: objects.iter().map(|object| object.0.clone()).collect(),
            events: events
                .into_iter()
                .map(TryInto::try_into)
                .collect::<crate::error::Result<_>>()?,
        }))
    }

    pub fn objects(&self) -> Vec<Arc<GenesisObject>> {
        self.0
            .objects
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }

    pub fn events(&self) -> Vec<Event> {
        self.0.events.iter().cloned().map(Into::into).collect()
    }
}

/// System transaction used to change the epoch
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// change-epoch = u64  ; next epoch
///                u64  ; protocol version
///                u64  ; storage charge
///                u64  ; computation charge
///                u64  ; storage rebate
///                u64  ; non-refundable storage fee
///                u64  ; epoch start timestamp
///                (vector system-package)
/// ```
#[derive(Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct ChangeEpoch(pub iota_sdk::types::ChangeEpoch);

#[uniffi::export]
impl ChangeEpoch {
    #[uniffi::constructor]
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        epoch: EpochId,
        protocol_version: ProtocolVersion,
        storage_charge: u64,
        computation_charge: u64,
        storage_rebate: u64,
        non_refundable_storage_fee: u64,
        epoch_start_timestamp_ms: u64,
        system_packages: Vec<Arc<SystemPackage>>,
    ) -> Self {
        Self(iota_sdk::types::ChangeEpoch {
            epoch,
            protocol_version,
            storage_charge,
            computation_charge,
            storage_rebate,
            non_refundable_storage_fee,
            epoch_start_timestamp_ms,
            system_packages: system_packages
                .into_iter()
                .map(|package| package.0.clone())
                .collect(),
        })
    }

    /// The next (to become) epoch ID.
    pub fn epoch(&self) -> EpochId {
        self.0.epoch
    }

    /// The protocol version in effect in the new epoch.
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.0.protocol_version
    }

    /// The total amount of gas charged for storage during the epoch.
    pub fn storage_charge(&self) -> u64 {
        self.0.storage_charge
    }

    /// The total amount of gas charged for computation during the epoch.
    pub fn computation_charge(&self) -> u64 {
        self.0.computation_charge
    }

    /// The amount of storage rebate refunded to the txn senders.
    pub fn storage_rebate(&self) -> u64 {
        self.0.storage_rebate
    }

    /// The non-refundable storage fee.
    pub fn non_refundable_storage_fee(&self) -> u64 {
        self.0.non_refundable_storage_fee
    }

    /// Unix timestamp when epoch started
    pub fn epoch_start_timestamp_ms(&self) -> u64 {
        self.0.epoch_start_timestamp_ms
    }

    /// System packages (specifically framework and move stdlib) that are
    /// written before the new epoch starts.
    pub fn system_packages(&self) -> Vec<Arc<SystemPackage>> {
        self.0
            .system_packages
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }
}

/// System package
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// system-package = u64                ; version
///                  (vector bytes)     ; modules
///                  (vector object-id) ; dependencies
/// ```
#[derive(Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct SystemPackage(pub iota_sdk::types::SystemPackage);

#[uniffi::export]
impl SystemPackage {
    #[uniffi::constructor]
    pub fn new(version: &Version, modules: Vec<Vec<u8>>, dependencies: Vec<Arc<ObjectId>>) -> Self {
        Self(iota_sdk::types::SystemPackage {
            version: **version,
            modules,
            dependencies: dependencies.into_iter().map(|dep| dep.0).collect(),
        })
    }

    pub fn version(&self) -> Version {
        self.0.version.into()
    }

    pub fn modules(&self) -> Vec<Vec<u8>> {
        self.0.modules.clone()
    }

    pub fn dependencies(&self) -> Vec<Arc<ObjectId>> {
        self.0
            .dependencies
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }
}

/// System transaction used to change the epoch
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// change-epoch-v2 = u64  ; next epoch
///                   u64  ; protocol version
///                   u64  ; storage charge
///                   u64  ; computation charge
///                   u64  ; computation charge burned
///                   u64  ; storage rebate
///                   u64  ; non-refundable storage fee
///                   u64  ; epoch start timestamp
///                   (vector system-package)
/// ```
#[derive(Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct ChangeEpochV2(pub iota_sdk::types::ChangeEpochV2);

#[uniffi::export]
impl ChangeEpochV2 {
    #[uniffi::constructor]
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        epoch: EpochId,
        protocol_version: ProtocolVersion,
        storage_charge: u64,
        computation_charge: u64,
        computation_charge_burned: u64,
        storage_rebate: u64,
        non_refundable_storage_fee: u64,
        epoch_start_timestamp_ms: u64,
        system_packages: Vec<Arc<SystemPackage>>,
    ) -> Self {
        Self(iota_sdk::types::ChangeEpochV2 {
            epoch,
            protocol_version,
            storage_charge,
            computation_charge,
            computation_charge_burned,
            storage_rebate,
            non_refundable_storage_fee,
            epoch_start_timestamp_ms,
            system_packages: system_packages
                .into_iter()
                .map(|package| package.0.clone())
                .collect(),
        })
    }

    /// The next (to become) epoch ID.
    pub fn epoch(&self) -> EpochId {
        self.0.epoch
    }

    /// The protocol version in effect in the new epoch.
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.0.protocol_version
    }

    /// The total amount of gas charged for storage during the epoch.
    pub fn storage_charge(&self) -> u64 {
        self.0.storage_charge
    }

    /// The total amount of gas charged for computation during the epoch.
    pub fn computation_charge(&self) -> u64 {
        self.0.computation_charge
    }

    /// The total amount of gas burned for computation during the epoch.
    pub fn computation_charge_burned(&self) -> u64 {
        self.0.computation_charge_burned
    }

    /// The amount of storage rebate refunded to the txn senders.
    pub fn storage_rebate(&self) -> u64 {
        self.0.storage_rebate
    }

    /// The non-refundable storage fee.
    pub fn non_refundable_storage_fee(&self) -> u64 {
        self.0.non_refundable_storage_fee
    }

    /// Unix timestamp when epoch started
    pub fn epoch_start_timestamp_ms(&self) -> u64 {
        self.0.epoch_start_timestamp_ms
    }

    /// System packages (specifically framework and move stdlib) that are
    /// written before the new epoch starts.
    pub fn system_packages(&self) -> Vec<Arc<SystemPackage>> {
        self.0
            .system_packages
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }
}

#[derive(Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct ChangeEpochV3(pub iota_sdk::types::ChangeEpochV3);

#[uniffi::export]
impl ChangeEpochV3 {
    #[uniffi::constructor]
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        epoch: EpochId,
        protocol_version: ProtocolVersion,
        storage_charge: u64,
        computation_charge: u64,
        computation_charge_burned: u64,
        storage_rebate: u64,
        non_refundable_storage_fee: u64,
        epoch_start_timestamp_ms: u64,
        system_packages: Vec<Arc<SystemPackage>>,
        eligible_active_validators: Vec<u64>,
    ) -> Self {
        Self(iota_sdk::types::ChangeEpochV3 {
            epoch,
            protocol_version,
            storage_charge,
            computation_charge,
            computation_charge_burned,
            storage_rebate,
            non_refundable_storage_fee,
            epoch_start_timestamp_ms,
            system_packages: system_packages
                .into_iter()
                .map(|package| package.0.clone())
                .collect(),
            eligible_active_validators,
        })
    }

    /// The next (to become) epoch ID.
    pub fn epoch(&self) -> EpochId {
        self.0.epoch
    }

    /// The protocol version in effect in the new epoch.
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.0.protocol_version
    }

    /// The total amount of gas charged for storage during the epoch.
    pub fn storage_charge(&self) -> u64 {
        self.0.storage_charge
    }

    /// The total amount of gas charged for computation during the epoch.
    pub fn computation_charge(&self) -> u64 {
        self.0.computation_charge
    }

    /// The total amount of gas burned for computation during the epoch.
    pub fn computation_charge_burned(&self) -> u64 {
        self.0.computation_charge_burned
    }

    /// The amount of storage rebate refunded to the txn senders.
    pub fn storage_rebate(&self) -> u64 {
        self.0.storage_rebate
    }

    /// The non-refundable storage fee.
    pub fn non_refundable_storage_fee(&self) -> u64 {
        self.0.non_refundable_storage_fee
    }

    /// Unix timestamp when epoch started
    pub fn epoch_start_timestamp_ms(&self) -> u64 {
        self.0.epoch_start_timestamp_ms
    }

    /// System packages (specifically framework and move stdlib) that are
    /// written before the new epoch starts.
    pub fn system_packages(&self) -> Vec<Arc<SystemPackage>> {
        self.0
            .system_packages
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }

    /// Vector of active validator indices eligible to take part in committee
    /// selection because they support the new, target protocol version.
    pub fn eligible_active_validators(&self) -> Vec<u64> {
        self.0.eligible_active_validators.clone()
    }
}

#[derive(Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
pub struct ChangeEpochV4(pub iota_sdk::types::ChangeEpochV4);

#[uniffi::export]
impl ChangeEpochV4 {
    #[uniffi::constructor]
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        epoch: EpochId,
        protocol_version: ProtocolVersion,
        storage_charge: u64,
        computation_charge: u64,
        computation_charge_burned: u64,
        storage_rebate: u64,
        non_refundable_storage_fee: u64,
        epoch_start_timestamp_ms: u64,
        system_packages: Vec<Arc<SystemPackage>>,
        eligible_active_validators: Vec<u64>,
        scores: Vec<u64>,
        adjust_rewards_by_score: bool,
    ) -> Self {
        Self(iota_sdk::types::ChangeEpochV4 {
            epoch,
            protocol_version,
            storage_charge,
            computation_charge,
            computation_charge_burned,
            storage_rebate,
            non_refundable_storage_fee,
            epoch_start_timestamp_ms,
            system_packages: system_packages
                .into_iter()
                .map(|package| package.0.clone())
                .collect(),
            eligible_active_validators,
            scores,
            adjust_rewards_by_score,
        })
    }

    /// The next (to become) epoch ID.
    pub fn epoch(&self) -> EpochId {
        self.0.epoch
    }

    /// The protocol version in effect in the new epoch.
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.0.protocol_version
    }

    /// The total amount of gas charged for storage during the epoch.
    pub fn storage_charge(&self) -> u64 {
        self.0.storage_charge
    }

    /// The total amount of gas charged for computation during the epoch.
    pub fn computation_charge(&self) -> u64 {
        self.0.computation_charge
    }

    /// The total amount of gas burned for computation during the epoch.
    pub fn computation_charge_burned(&self) -> u64 {
        self.0.computation_charge_burned
    }

    /// The amount of storage rebate refunded to the txn senders.
    pub fn storage_rebate(&self) -> u64 {
        self.0.storage_rebate
    }

    /// The non-refundable storage fee.
    pub fn non_refundable_storage_fee(&self) -> u64 {
        self.0.non_refundable_storage_fee
    }

    /// Unix timestamp when epoch started
    pub fn epoch_start_timestamp_ms(&self) -> u64 {
        self.0.epoch_start_timestamp_ms
    }

    /// System packages (specifically framework and move stdlib) that are
    /// written before the new epoch starts.
    pub fn system_packages(&self) -> Vec<Arc<SystemPackage>> {
        self.0
            .system_packages
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }

    /// Vector of active validator indices eligible to take part in committee
    /// selection because they support the new, target protocol version.
    pub fn eligible_active_validators(&self) -> Vec<u64> {
        self.0.eligible_active_validators.clone()
    }

    /// Vector of scores relative to the past epoch performance of each
    /// validator, ordered by the past epoch's validator index.
    pub fn scores(&self) -> Vec<u64> {
        self.0.scores.clone()
    }

    /// Whether to adjust validator rewards based on score.
    pub fn adjust_rewards_by_score(&self) -> bool {
        self.0.adjust_rewards_by_score
    }
}

/// Randomness update
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// randomness-state-update = u64 u64 bytes u64
/// ```
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct RandomnessStateUpdate {
    /// Epoch of the randomness state update transaction
    pub epoch: u64,
    /// Randomness round of the update
    pub randomness_round: u64,
    /// Updated random bytes
    pub random_bytes: Vec<u8>,
    /// The initial version of the randomness object that it was shared at
    pub randomness_obj_initial_shared_version: Arc<Version>,
}

impl From<RandomnessStateUpdate> for iota_sdk::types::RandomnessStateUpdate {
    fn from(value: RandomnessStateUpdate) -> Self {
        Self {
            epoch: value.epoch,
            randomness_round: value.randomness_round.into(),
            random_bytes: value.random_bytes,
            randomness_obj_initial_shared_version: **value.randomness_obj_initial_shared_version,
        }
    }
}

impl From<iota_sdk::types::RandomnessStateUpdate> for RandomnessStateUpdate {
    fn from(value: iota_sdk::types::RandomnessStateUpdate) -> Self {
        Self {
            epoch: value.epoch,
            randomness_round: value.randomness_round.value(),
            random_bytes: value.random_bytes,
            randomness_obj_initial_shared_version: Arc::new(
                value.randomness_obj_initial_shared_version.into(),
            ),
        }
    }
}

/// A complete set of transaction deny rules.
///
/// The deny lists are exposed as sequences over the FFI; converting into the
/// underlying set-typed Rust representation sorts and deduplicates them, so
/// the BCS encoding is canonical regardless of the order supplied here.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// deny-rule-set = (vector address)   ; denied addresses
///                 (vector object-id) ; denied objects
///                 (vector object-id) ; denied packages
///                 bool               ; package publish disabled
///                 bool               ; package upgrade disabled
///                 bool               ; shared object disabled
///                 bool               ; user transaction disabled
///                 bool               ; receiving objects disabled
///                 bool               ; move authenticator disabled
/// ```
#[derive(Clone, uniffi::Record)]
pub struct DenyRuleSet {
    /// Addresses denied as transaction sender or gas sponsor. A denied
    /// address can still receive objects.
    pub denied_addresses: Vec<Arc<Address>>,
    /// Objects denied as transaction inputs or receiving objects.
    pub denied_objects: Vec<Arc<ObjectId>>,
    /// Packages denied as a (transitive) dependency of any command; upgrading
    /// a denied package is denied too.
    pub denied_packages: Vec<Arc<ObjectId>>,
    /// Denies all package publishing.
    pub package_publish_disabled: bool,
    /// Denies all package upgrades.
    pub package_upgrade_disabled: bool,
    /// Denies transactions that use shared objects as inputs.
    pub shared_object_disabled: bool,
    /// Denies all user transactions (kill switch).
    pub user_transaction_disabled: bool,
    /// Denies transactions that contain receiving objects.
    pub receiving_objects_disabled: bool,
    /// Denies transactions signed with a Move authenticator.
    pub move_authenticator_disabled: bool,
}

impl From<DenyRuleSet> for iota_sdk::types::DenyRuleSet {
    fn from(value: DenyRuleSet) -> Self {
        Self {
            denied_addresses: value.denied_addresses.iter().map(|a| a.0).collect(),
            denied_objects: value.denied_objects.iter().map(|o| o.0).collect(),
            denied_packages: value.denied_packages.iter().map(|o| o.0).collect(),
            package_publish_disabled: value.package_publish_disabled,
            package_upgrade_disabled: value.package_upgrade_disabled,
            shared_object_disabled: value.shared_object_disabled,
            user_transaction_disabled: value.user_transaction_disabled,
            receiving_objects_disabled: value.receiving_objects_disabled,
            move_authenticator_disabled: value.move_authenticator_disabled,
        }
    }
}

impl From<iota_sdk::types::DenyRuleSet> for DenyRuleSet {
    fn from(value: iota_sdk::types::DenyRuleSet) -> Self {
        Self {
            denied_addresses: value
                .denied_addresses
                .into_iter()
                .map(Into::into)
                .map(Arc::new)
                .collect(),
            denied_objects: value
                .denied_objects
                .into_iter()
                .map(Into::into)
                .map(Arc::new)
                .collect(),
            denied_packages: value
                .denied_packages
                .into_iter()
                .map(Into::into)
                .map(Arc::new)
                .collect(),
            package_publish_disabled: value.package_publish_disabled,
            package_upgrade_disabled: value.package_upgrade_disabled,
            shared_object_disabled: value.shared_object_disabled,
            user_transaction_disabled: value.user_transaction_disabled,
            receiving_objects_disabled: value.receiving_objects_disabled,
            move_authenticator_disabled: value.move_authenticator_disabled,
        }
    }
}

/// Update of the on-chain transaction deny rules.
///
/// Carries an add/remove delta for each deny list plus the absolute switch
/// states. The added and removed sets of a list are disjoint by producer
/// contract; converting into the underlying set-typed Rust representation
/// sorts and deduplicates the lists.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// transaction-deny-rules-update = u64               ; epoch
///                                 u64               ; round
///                                 (vector address)  ; added addresses
///                                 (vector address)  ; removed addresses
///                                 (vector object-id) ; added objects
///                                 (vector object-id) ; removed objects
///                                 (vector object-id) ; added packages
///                                 (vector object-id) ; removed packages
///                                 bool              ; package publish disabled
///                                 bool              ; package upgrade disabled
///                                 bool              ; shared object disabled
///                                 bool              ; user transaction disabled
///                                 bool              ; receiving objects disabled
///                                 bool              ; move authenticator disabled
///                                 version           ; initial shared version
/// ```
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct TransactionDenyRulesUpdate {
    /// Epoch of the deny-rules update transaction
    pub epoch: u64,
    /// Consensus round of the update
    pub round: u64,
    /// Addresses added to the sender-or-sponsor deny list.
    pub added_addresses: Vec<Arc<Address>>,
    /// Addresses removed from the sender-or-sponsor deny list.
    pub removed_addresses: Vec<Arc<Address>>,
    /// Objects added to the input-or-receiving deny list.
    pub added_objects: Vec<Arc<ObjectId>>,
    /// Objects removed from the input-or-receiving deny list.
    pub removed_objects: Vec<Arc<ObjectId>>,
    /// Packages added to the dependency deny list.
    pub added_packages: Vec<Arc<ObjectId>>,
    /// Packages removed from the dependency deny list.
    pub removed_packages: Vec<Arc<ObjectId>>,
    /// Denies all package publishing.
    pub package_publish_disabled: bool,
    /// Denies all package upgrades.
    pub package_upgrade_disabled: bool,
    /// Denies transactions that use shared objects as inputs.
    pub shared_object_disabled: bool,
    /// Denies all user transactions (kill switch).
    pub user_transaction_disabled: bool,
    /// Denies transactions that contain receiving objects.
    pub receiving_objects_disabled: bool,
    /// Denies transactions signed with a Move authenticator.
    pub move_authenticator_disabled: bool,
    /// The initial version of the deny-rules object that it was shared at
    pub deny_rules_obj_initial_shared_version: Arc<Version>,
}

impl From<TransactionDenyRulesUpdate> for iota_sdk::types::TransactionDenyRulesUpdate {
    fn from(value: TransactionDenyRulesUpdate) -> Self {
        Self {
            epoch: value.epoch,
            round: value.round,
            added_addresses: value.added_addresses.iter().map(|a| a.0).collect(),
            removed_addresses: value.removed_addresses.iter().map(|a| a.0).collect(),
            added_objects: value.added_objects.iter().map(|o| o.0).collect(),
            removed_objects: value.removed_objects.iter().map(|o| o.0).collect(),
            added_packages: value.added_packages.iter().map(|o| o.0).collect(),
            removed_packages: value.removed_packages.iter().map(|o| o.0).collect(),
            package_publish_disabled: value.package_publish_disabled,
            package_upgrade_disabled: value.package_upgrade_disabled,
            shared_object_disabled: value.shared_object_disabled,
            user_transaction_disabled: value.user_transaction_disabled,
            receiving_objects_disabled: value.receiving_objects_disabled,
            move_authenticator_disabled: value.move_authenticator_disabled,
            deny_rules_obj_initial_shared_version: **value.deny_rules_obj_initial_shared_version,
        }
    }
}

impl From<iota_sdk::types::TransactionDenyRulesUpdate> for TransactionDenyRulesUpdate {
    fn from(value: iota_sdk::types::TransactionDenyRulesUpdate) -> Self {
        fn arcs<T, U: From<T>>(items: impl IntoIterator<Item = T>) -> Vec<Arc<U>> {
            items.into_iter().map(|x| Arc::new(x.into())).collect()
        }
        Self {
            epoch: value.epoch,
            round: value.round,
            added_addresses: arcs(value.added_addresses),
            removed_addresses: arcs(value.removed_addresses),
            added_objects: arcs(value.added_objects),
            removed_objects: arcs(value.removed_objects),
            added_packages: arcs(value.added_packages),
            removed_packages: arcs(value.removed_packages),
            package_publish_disabled: value.package_publish_disabled,
            package_upgrade_disabled: value.package_upgrade_disabled,
            shared_object_disabled: value.shared_object_disabled,
            user_transaction_disabled: value.user_transaction_disabled,
            receiving_objects_disabled: value.receiving_objects_disabled,
            move_authenticator_disabled: value.move_authenticator_disabled,
            deny_rules_obj_initial_shared_version: Arc::new(
                value.deny_rules_obj_initial_shared_version.into(),
            ),
        }
    }
}

/// Operation run at the end of an epoch
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// end-of-epoch-transaction-kind =  %d00 change-epoch     ; ChangeEpoch
///                               =/ %d01 change-epoch-v2  ; ChangeEpochV2
///                               =/ %d02 change-epoch-v3  ; ChangeEpochV3
///                               =/ %d03 change-epoch-v4  ; ChangeEpochV4
///                               =/ %d04                  ; TransactionDenyRulesCreate
/// ```
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Enum)]
#[uniffi::export(Debug, Eq)]
pub enum EndOfEpochTransactionKind {
    ChangeEpoch { tx: Arc<ChangeEpoch> },
    ChangeEpochV2 { tx: Arc<ChangeEpochV2> },
    ChangeEpochV3 { tx: Arc<ChangeEpochV3> },
    ChangeEpochV4 { tx: Arc<ChangeEpochV4> },
    TransactionDenyRulesCreate,
}

impl From<iota_sdk::types::EndOfEpochTransactionKind> for EndOfEpochTransactionKind {
    fn from(value: iota_sdk::types::EndOfEpochTransactionKind) -> Self {
        match value {
            iota_sdk::types::EndOfEpochTransactionKind::ChangeEpoch(tx) => Self::ChangeEpoch {
                tx: Arc::new(tx.into()),
            },
            iota_sdk::types::EndOfEpochTransactionKind::ChangeEpochV2(tx) => Self::ChangeEpochV2 {
                tx: Arc::new(tx.into()),
            },
            iota_sdk::types::EndOfEpochTransactionKind::ChangeEpochV3(tx) => Self::ChangeEpochV3 {
                tx: Arc::new(tx.into()),
            },
            iota_sdk::types::EndOfEpochTransactionKind::ChangeEpochV4(tx) => Self::ChangeEpochV4 {
                tx: Arc::new(tx.into()),
            },
            iota_sdk::types::EndOfEpochTransactionKind::TransactionDenyRulesCreate => {
                Self::TransactionDenyRulesCreate
            }
            _ => unimplemented!("a new enum variant was added and needs to be handled"),
        }
    }
}

impl From<EndOfEpochTransactionKind> for iota_sdk::types::EndOfEpochTransactionKind {
    fn from(value: EndOfEpochTransactionKind) -> Self {
        match value {
            EndOfEpochTransactionKind::ChangeEpoch { tx } => Self::ChangeEpoch(tx.0.clone()),
            EndOfEpochTransactionKind::ChangeEpochV2 { tx } => Self::ChangeEpochV2(tx.0.clone()),
            EndOfEpochTransactionKind::ChangeEpochV3 { tx } => Self::ChangeEpochV3(tx.0.clone()),
            EndOfEpochTransactionKind::ChangeEpochV4 { tx } => Self::ChangeEpochV4(tx.0.clone()),
            EndOfEpochTransactionKind::TransactionDenyRulesCreate => {
                Self::TransactionDenyRulesCreate
            }
        }
    }
}

/// Payment information for executing a transaction
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// gas-payment = (vector object-reference) ; gas coin objects
///               address                   ; owner
///               u64                       ; price
///               u64                       ; budget
/// ```
#[derive(Clone, uniffi::Record)]
pub struct GasPayment {
    pub objects: Vec<ObjectReference>,
    /// Owner of the gas objects, either the transaction sender or a sponsor
    pub owner: Arc<Address>,
    /// Gas unit price to use when charging for computation
    ///
    /// Must be greater-than-or-equal-to the network's current RGP (reference
    /// gas price)
    pub price: u64,
    /// Total budget willing to spend for the execution of a transaction
    pub budget: u64,
}

impl From<iota_sdk::types::GasPayment> for GasPayment {
    fn from(value: iota_sdk::types::GasPayment) -> Self {
        Self {
            objects: value.objects.into_iter().map(Into::into).collect(),
            owner: Arc::new(value.owner.into()),
            price: value.price,
            budget: value.budget,
        }
    }
}

impl From<GasPayment> for iota_sdk::types::GasPayment {
    fn from(value: GasPayment) -> Self {
        Self {
            objects: value.objects.into_iter().map(Into::into).collect(),
            owner: value.owner.0,
            price: value.price,
            budget: value.budget,
        }
    }
}

/// The output or effects of executing a transaction
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// transaction-effects =  %d00 effects-v1
///                     =/ %d01 effects-v2
/// ```
#[derive(Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct TransactionEffects(pub iota_sdk::types::TransactionEffects);

#[uniffi::export]
impl TransactionEffects {
    #[uniffi::constructor]
    pub fn new_v1(effects: TransactionEffectsV1) -> Self {
        Self(iota_sdk::types::TransactionEffects::V1(Box::new(
            effects.into(),
        )))
    }

    pub fn is_v1(&self) -> bool {
        self.0.is_v1()
    }

    pub fn as_v1(&self) -> TransactionEffectsV1 {
        self.0.as_v1().clone().into()
    }

    pub fn digest(&self) -> TransactionEffectsDigest {
        self.0.digest().into()
    }
}

/// A TTL for a transaction
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// transaction-expiration =  %d00      ; none
///                        =/ %d01 u64  ; epoch
/// ```
#[uniffi::remote(Enum)]
#[non_exhaustive]
pub enum TransactionExpiration {
    /// The transaction has no expiration
    None,
    /// Validators won't sign a transaction unless the expiration Epoch
    /// is greater than or equal to the current epoch
    Epoch(u64),
}

/// An argument to a programmable transaction command
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// argument    =  argument-gas
///             =/ argument-input
///             =/ argument-result
///             =/ argument-nested-result
///
/// argument-gas            = %d00
/// argument-input          = %d01 u16
/// argument-result         = %d02 u16
/// argument-nested-result  = %d03 u16 u16
/// ```
#[derive(Debug, derive_more::Deref, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct Argument(iota_sdk::types::Argument);

#[uniffi::export]
impl Argument {
    /// The gas coin. The gas coin can only be used by-ref, except for with
    /// `TransferObjects`, which can use it by-value.
    #[uniffi::constructor]
    pub fn new_gas() -> Self {
        Self(iota_sdk::types::Argument::Gas)
    }

    /// One of the input objects or primitive values (from
    /// `ProgrammableTransaction` inputs)
    #[uniffi::constructor]
    pub fn new_input(input: u16) -> Self {
        Self(iota_sdk::types::Argument::Input(input))
    }

    /// The result of another command (from `ProgrammableTransaction` commands)
    #[uniffi::constructor]
    pub fn new_result(result: u16) -> Self {
        Self(iota_sdk::types::Argument::Result(result))
    }

    /// Like a `Result` but it accesses a nested result. Currently, the only
    /// usage of this is to access a value from a Move call with multiple
    /// return values.
    // (command index, subresult index)
    #[uniffi::constructor]
    pub fn new_nested_result(command_index: u16, subresult_index: u16) -> Self {
        Self(iota_sdk::types::Argument::NestedResult(
            command_index,
            subresult_index,
        ))
    }

    /// Get the nested result for this result at the given index. Returns None
    /// if this is not a Result.
    pub fn get_nested_result(&self, ix: u16) -> Option<Arc<Argument>> {
        self.0.get_nested_result(ix).map(Self).map(Arc::new)
    }
}

/// Command to call a move function
///
/// Functions that can be called by a `MoveCall` command are those that have a
/// function signature that is either `entry` or `public` (which don't have a
/// reference return type).
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// move-call = object-id           ; package id
///             identifier          ; module name
///             identifier          ; function name
///             (vector type-tag)   ; type arguments, if any
///             (vector argument)   ; input arguments
/// ```
#[derive(Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct MoveCall(iota_sdk::types::MoveCall);

#[uniffi::export]
impl MoveCall {
    #[uniffi::constructor]
    pub fn new(
        package: &ObjectId,
        module: &Identifier,
        function: &Identifier,
        type_arguments: Vec<Arc<TypeTag>>,
        arguments: Vec<Arc<Argument>>,
    ) -> Self {
        Self(iota_sdk::types::MoveCall {
            package: package.0,
            module: module.0.clone(),
            function: function.0.clone(),
            type_arguments: type_arguments
                .iter()
                .map(|type_argument| type_argument.0.clone())
                .collect(),
            arguments: arguments.iter().map(|argument| argument.0).collect(),
        })
    }

    /// The package containing the module and function.
    pub fn package(&self) -> ObjectId {
        self.0.package.into()
    }

    /// The specific module in the package containing the function.
    pub fn module(&self) -> Identifier {
        self.0.module.clone().into()
    }

    /// The function to be called.
    pub fn function(&self) -> Identifier {
        self.0.function.clone().into()
    }

    /// The type arguments to the function.
    pub fn type_arguments(&self) -> Vec<Arc<TypeTag>> {
        self.0
            .type_arguments
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }

    /// The arguments to the function.
    pub fn arguments(&self) -> Vec<Arc<Argument>> {
        self.0
            .arguments
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }
}

/// A shared object input to a programmable transaction
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct SharedObjectReference {
    object_id: Arc<ObjectId>,
    initial_shared_version: Arc<Version>,
    mutable: bool,
}

impl From<iota_sdk::types::SharedObjectReference> for SharedObjectReference {
    fn from(value: iota_sdk::types::SharedObjectReference) -> Self {
        Self {
            object_id: Arc::new((value.object_id).into()),
            initial_shared_version: Arc::new(value.initial_shared_version.into()),
            mutable: value.mutable,
        }
    }
}

impl From<SharedObjectReference> for iota_sdk::types::SharedObjectReference {
    fn from(value: SharedObjectReference) -> Self {
        Self::new(
            **value.object_id,
            **value.initial_shared_version,
            value.mutable,
        )
    }
}

crate::export_iota_types_bcs_conversion!(
    Command,
    Input,
    TransactionKind,
    SignedTransaction,
    RandomnessStateUpdate,
    DenyRuleSet,
    TransactionDenyRulesUpdate,
    GasPayment
);
crate::export_remote_types_bcs_conversion!(TransactionExpiration);
crate::export_iota_types_objects_bcs_conversion!(
    Transaction,
    TransactionV1,
    ProgrammableTransaction,
    TransferObjects,
    SplitCoins,
    MergeCoins,
    Publish,
    MakeMoveVector,
    Upgrade,
    ConsensusCommitPrologueV1,
    ConsensusDeterminedVersionAssignments,
    CanceledTransaction,
    VersionAssignment,
    GenesisTransaction,
    ChangeEpoch,
    SystemPackage,
    ChangeEpochV2,
    TransactionEffects,
    Argument,
    MoveCall,
);
crate::export_iota_types_json_conversion!(
    Command,
    Input,
    TransactionKind,
    SignedTransaction,
    RandomnessStateUpdate,
    DenyRuleSet,
    TransactionDenyRulesUpdate,
    GasPayment
);
crate::export_remote_types_json_conversion!(TransactionExpiration);
crate::export_iota_types_objects_json_conversion!(
    Transaction,
    TransactionV1,
    ProgrammableTransaction,
    TransferObjects,
    SplitCoins,
    MergeCoins,
    Publish,
    MakeMoveVector,
    Upgrade,
    ConsensusCommitPrologueV1,
    ConsensusDeterminedVersionAssignments,
    CanceledTransaction,
    VersionAssignment,
    GenesisTransaction,
    ChangeEpoch,
    SystemPackage,
    ChangeEpochV2,
    TransactionEffects,
    Argument,
    MoveCall,
);
