// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_types::{GasCostSummary, TransactionExpiration};

use crate::types::{
    address::Address,
    checkpoint::CheckpointTimestamp,
    digest::{CheckpointDigest, ConsensusCommitDigest, TransactionDigest, TransactionEventsDigest},
    events::Event,
    execution_status::ExecutionStatus,
    object::{GenesisObject, ObjectId, ObjectReference, Version},
    signature::UserSignature,
    struct_tag::Identifier,
    transaction::v1::TransactionEffectsV1,
    type_tag::TypeTag,
};

pub mod v1;

/// A transaction
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// transaction = %x00 transaction-v1
///
/// transaction-v1 = transaction-kind address gas-payment transaction-expiration
/// ```
#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct Transaction(pub iota_types::Transaction);

#[uniffi::export]
impl Transaction {
    #[uniffi::constructor]
    pub fn new(
        kind: &TransactionKind,
        sender: &Address,
        gas_payment: GasPayment,
        expiration: TransactionExpiration,
    ) -> Self {
        Self(iota_types::Transaction {
            kind: kind.0.clone(),
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
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct SignedTransaction {
    pub transaction: Arc<Transaction>,
    pub signatures: Vec<Arc<UserSignature>>,
}

impl From<iota_types::SignedTransaction> for SignedTransaction {
    fn from(value: iota_types::SignedTransaction) -> Self {
        Self {
            transaction: Arc::new(value.transaction.into()),
            signatures: value
                .signatures
                .into_iter()
                .map(Into::into)
                .map(Arc::new)
                .collect(),
        }
    }
}

impl From<SignedTransaction> for iota_types::SignedTransaction {
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
/// transaction-kind    =  %x00 ptb
///                     =/ %x01 change-epoch
///                     =/ %x02 genesis-transaction
///                     =/ %x03 consensus-commit-prologue
///                     =/ %x04 authenticator-state-update
///                     =/ %x05 (vector end-of-epoch-transaction-kind)
///                     =/ %x06 randomness-state-update
///                     =/ %x07 consensus-commit-prologue-v2
///                     =/ %x08 consensus-commit-prologue-v3
/// ```
#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct TransactionKind(pub iota_types::TransactionKind);

#[uniffi::export]
impl TransactionKind {
    #[uniffi::constructor]
    pub fn programmable_transaction(tx: &ProgrammableTransaction) -> Self {
        Self(iota_types::TransactionKind::ProgrammableTransaction(
            tx.0.clone(),
        ))
    }

    #[uniffi::constructor]
    pub fn genesis(tx: &GenesisTransaction) -> Self {
        Self(iota_types::TransactionKind::Genesis(tx.0.clone()))
    }

    #[uniffi::constructor]
    pub fn consensus_commit_prologue_v1(tx: &ConsensusCommitPrologueV1) -> Self {
        Self(iota_types::TransactionKind::ConsensusCommitPrologueV1(
            tx.0.clone(),
        ))
    }

    #[uniffi::constructor]
    pub fn authenticator_state_update_v1(tx: &AuthenticatorStateUpdateV1) -> Self {
        Self(iota_types::TransactionKind::AuthenticatorStateUpdateV1(
            tx.0.clone(),
        ))
    }

    #[uniffi::constructor]
    pub fn end_of_epoch(tx: Vec<Arc<EndOfEpochTransactionKind>>) -> Self {
        Self(iota_types::TransactionKind::EndOfEpoch(
            tx.into_iter().map(|tx| tx.0.clone()).collect(),
        ))
    }

    #[uniffi::constructor]
    pub fn randomness_state_update(tx: &RandomnessStateUpdate) -> Self {
        Self(iota_types::TransactionKind::RandomnessStateUpdate(
            tx.0.clone(),
        ))
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
#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct ProgrammableTransaction(pub iota_types::ProgrammableTransaction);

#[uniffi::export]
impl ProgrammableTransaction {
    #[uniffi::constructor]
    pub fn new(inputs: Vec<Arc<Input>>, commands: Vec<Arc<Command>>) -> Self {
        Self(iota_types::ProgrammableTransaction {
            inputs: inputs
                .iter()
                .cloned()
                .map(|input| input.0.clone())
                .collect(),
            commands: commands
                .iter()
                .cloned()
                .map(|command| command.0.clone())
                .collect(),
        })
    }

    /// Input objects or primitive values
    pub fn inputs(&self) -> Vec<Arc<Input>> {
        self.0
            .inputs
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }

    /// The commands to be executed sequentially. A failure in any command will
    /// result in the failure of the entire transaction.
    pub fn commands(&self) -> Vec<Arc<Command>> {
        self.0
            .commands
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }
}

/// An input to a user transaction
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// input = input-pure / input-immutable-or-owned / input-shared / input-receiving
///
/// input-pure                  = %x00 bytes
/// input-immutable-or-owned    = %x01 object-ref
/// input-shared                = %x02 object-id u64 bool
/// input-receiving             = %x04 object-ref
/// ```
#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct Input(pub iota_types::Input);

#[uniffi::export]
impl Input {
    /// For normal operations this is required to be a move primitive type and
    /// not contain structs or objects.
    #[uniffi::constructor]
    pub fn new_pure(value: Vec<u8>) -> Self {
        Self(iota_types::Input::Pure { value })
    }

    /// A move object that is either immutable or address owned
    #[uniffi::constructor]
    pub fn new_immutable_or_owned(object_ref: ObjectReference) -> Self {
        Self(iota_types::Input::ImmutableOrOwned(object_ref.into()))
    }

    /// A move object whose owner is "Shared"
    #[uniffi::constructor]
    pub fn new_shared(object_id: &ObjectId, initial_shared_version: u64, mutable: bool) -> Self {
        Self(iota_types::Input::Shared {
            object_id: object_id.0,
            initial_shared_version,
            mutable,
        })
    }

    #[uniffi::constructor]
    pub fn new_receiving(object_ref: ObjectReference) -> Self {
        Self(iota_types::Input::Receiving(object_ref.into()))
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
/// command-move-call           = %x00 move-call
/// command-transfer-objects    = %x01 transfer-objects
/// command-split-coins         = %x02 split-coins
/// command-merge-coins         = %x03 merge-coins
/// command-publish             = %x04 publish
/// command-make-move-vector    = %x05 make-move-vector
/// command-upgrade             = %x06 upgrade
/// ```
#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct Command(pub iota_types::Command);

#[uniffi::export]
impl Command {
    /// A call to either an entry or a public Move function
    #[uniffi::constructor]
    pub fn new_move_call(move_call: &MoveCall) -> Self {
        Self(iota_types::Command::MoveCall(move_call.0.clone()))
    }

    /// It sends n-objects to the specified address. These objects must have
    /// store (public transfer) and either the previous owner must be an
    /// address or the object must be newly created.
    #[uniffi::constructor]
    pub fn new_transfer_objects(transfer_objects: &TransferObjects) -> Self {
        Self(iota_types::Command::TransferObjects(
            transfer_objects.0.clone(),
        ))
    }

    /// It splits off some amounts into a new coins with those amounts
    #[uniffi::constructor]
    pub fn new_split_coins(split_coins: &SplitCoins) -> Self {
        Self(iota_types::Command::SplitCoins(split_coins.0.clone()))
    }

    /// It merges n-coins into the first coin
    #[uniffi::constructor]
    pub fn new_merge_coins(merge_coins: &MergeCoins) -> Self {
        Self(iota_types::Command::MergeCoins(merge_coins.0.clone()))
    }

    /// Publishes a Move package. It takes the package bytes and a list of the
    /// package's transitive dependencies to link against on-chain.
    #[uniffi::constructor]
    pub fn new_publish(publish: &Publish) -> Self {
        Self(iota_types::Command::Publish(publish.0.clone()))
    }

    /// Given n-values of the same type, it constructs a vector. For non objects
    /// or an empty vector, the type tag must be specified.
    #[uniffi::constructor]
    pub fn new_make_move_vector(make_move_vector: &MakeMoveVector) -> Self {
        Self(iota_types::Command::MakeMoveVector(
            make_move_vector.0.clone(),
        ))
    }

    /// Upgrades a Move package
    /// Takes (in order):
    /// 1. A vector of serialized modules for the package.
    /// 2. A vector of object ids for the transitive dependencies of the new
    ///    package.
    /// 3. The object ID of the package being upgraded.
    /// 4. An argument holding the `UpgradeTicket` that must have been produced
    ///    from an earlier command in the same programmable transaction.
    #[uniffi::constructor]
    pub fn new_upgrade(upgrade: &Upgrade) -> Self {
        Self(iota_types::Command::Upgrade(upgrade.0.clone()))
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
#[derive(Clone, Debug, PartialEq, Eq, derive_more::From, uniffi::Object)]
pub struct TransferObjects(pub iota_types::TransferObjects);

#[uniffi::export]
impl TransferObjects {
    #[uniffi::constructor]
    pub fn new(objects: Vec<Arc<Argument>>, address: Arc<Argument>) -> Self {
        Self(iota_types::TransferObjects {
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
#[derive(Clone, Debug, PartialEq, Eq, derive_more::From, uniffi::Object)]
pub struct SplitCoins(pub iota_types::SplitCoins);

#[uniffi::export]
impl SplitCoins {
    #[uniffi::constructor]
    pub fn new(coin: &Argument, amounts: Vec<Arc<Argument>>) -> Self {
        Self(iota_types::SplitCoins {
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
#[derive(Clone, Debug, PartialEq, Eq, derive_more::From, uniffi::Object)]
pub struct MergeCoins(pub iota_types::MergeCoins);

#[uniffi::export]
impl MergeCoins {
    #[uniffi::constructor]
    pub fn new(coin: &Argument, coins_to_merge: Vec<Arc<Argument>>) -> Self {
        Self(iota_types::MergeCoins {
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
#[derive(Clone, Debug, PartialEq, Eq, derive_more::From, uniffi::Object)]
pub struct Publish(pub iota_types::Publish);

#[uniffi::export]
impl Publish {
    #[uniffi::constructor]
    pub fn new(modules: Vec<Vec<u8>>, dependencies: Vec<Arc<ObjectId>>) -> Self {
        Self(iota_types::Publish {
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
#[derive(Clone, Debug, PartialEq, Eq, derive_more::From, uniffi::Object)]
pub struct MakeMoveVector(pub iota_types::MakeMoveVector);

#[uniffi::export]
impl MakeMoveVector {
    #[uniffi::constructor]
    pub fn new(type_tag: Option<Arc<TypeTag>>, elements: Vec<Arc<Argument>>) -> Self {
        Self(iota_types::MakeMoveVector {
            type_: type_tag.map(|type_tag| type_tag.0.clone()),
            elements: elements.iter().map(|element| element.0).collect(),
        })
    }

    /// Type of the individual elements
    ///
    /// This is required to be set when the type can't be inferred, for example
    /// when the set of provided arguments are all pure input values.
    pub fn type_tag(&self) -> Option<Arc<TypeTag>> {
        self.0.type_.clone().map(Into::into).map(Arc::new)
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
#[derive(Clone, Debug, PartialEq, Eq, derive_more::From, uniffi::Object)]
pub struct Upgrade(pub iota_types::Upgrade);

#[uniffi::export]
impl Upgrade {
    #[uniffi::constructor]
    pub fn new(
        modules: Vec<Vec<u8>>,
        dependencies: Vec<Arc<ObjectId>>,
        package: Arc<ObjectId>,
        ticket: Arc<Argument>,
    ) -> Self {
        Self(iota_types::Upgrade {
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
#[derive(Clone, Debug, PartialEq, Eq, derive_more::From, uniffi::Object)]
pub struct ConsensusCommitPrologueV1(pub iota_types::ConsensusCommitPrologueV1);

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
        Self(iota_types::ConsensusCommitPrologueV1 {
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

#[derive(Clone, Debug, PartialEq, Eq, derive_more::From, uniffi::Object)]
pub struct ConsensusDeterminedVersionAssignments(
    pub iota_types::ConsensusDeterminedVersionAssignments,
);

#[uniffi::export]
impl ConsensusDeterminedVersionAssignments {
    #[uniffi::constructor]
    pub fn new_cancelled_transactions(
        cancelled_transactions: Vec<Arc<CancelledTransaction>>,
    ) -> Self {
        Self(
            iota_types::ConsensusDeterminedVersionAssignments::CancelledTransactions {
                cancelled_transactions: cancelled_transactions
                    .into_iter()
                    .map(|v| v.0.clone())
                    .collect(),
            },
        )
    }

    pub fn is_cancelled_transactions(&self) -> bool {
        matches!(
            self.0,
            iota_types::ConsensusDeterminedVersionAssignments::CancelledTransactions { .. }
        )
    }

    pub fn as_cancelled_transactions_opt(&self) -> Option<Vec<Arc<CancelledTransaction>>> {
        let iota_types::ConsensusDeterminedVersionAssignments::CancelledTransactions {
            cancelled_transactions,
        } = &self.0;

        Some(
            cancelled_transactions
                .iter()
                .cloned()
                .map(Into::into)
                .map(Arc::new)
                .collect(),
        )
    }

    pub fn as_cancelled_transactions(&self) -> Vec<Arc<CancelledTransaction>> {
        self.as_cancelled_transactions_opt()
            .expect("not a CancelledTransactions")
    }
}

/// A transaction that was cancelled
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// cancelled-transaction = digest (vector version-assignment)
/// ```
#[derive(Clone, Debug, PartialEq, Eq, derive_more::From, uniffi::Object)]
pub struct CancelledTransaction(pub iota_types::CancelledTransaction);

#[uniffi::export]
impl CancelledTransaction {
    #[uniffi::constructor]
    pub fn new(
        digest: &TransactionDigest,
        version_assignments: Vec<Arc<VersionAssignment>>,
    ) -> Self {
        Self(iota_types::CancelledTransaction {
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
#[derive(Clone, Debug, PartialEq, Eq, derive_more::From, uniffi::Object)]
pub struct VersionAssignment(iota_types::VersionAssignment);

#[uniffi::export]
impl VersionAssignment {
    #[uniffi::constructor]
    pub fn new(object_id: &ObjectId, version: u64) -> Self {
        Self(iota_types::VersionAssignment {
            object_id: object_id.0,
            version,
        })
    }

    pub fn object_id(&self) -> ObjectId {
        self.0.object_id.into()
    }

    pub fn version(&self) -> Version {
        self.0.version
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
#[derive(Clone, Debug, PartialEq, Eq, derive_more::From, uniffi::Object)]
pub struct GenesisTransaction(iota_types::GenesisTransaction);

#[uniffi::export]
impl GenesisTransaction {
    #[uniffi::constructor]
    pub fn new(objects: Vec<Arc<GenesisObject>>, events: Vec<Event>) -> Self {
        Self(iota_types::GenesisTransaction {
            objects: objects.iter().map(|object| object.0.clone()).collect(),
            events: events.iter().cloned().map(Into::into).collect(),
        })
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

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct ChangeEpoch(pub iota_types::ChangeEpoch);

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct ChangeEpochV2(pub iota_types::ChangeEpochV2);

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct AuthenticatorStateExpire(pub iota_types::AuthenticatorStateExpire);

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct AuthenticatorStateUpdateV1(pub iota_types::AuthenticatorStateUpdateV1);

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct ExecutionTimeObservations(pub iota_types::ExecutionTimeObservations);

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct RandomnessStateUpdate(pub iota_types::RandomnessStateUpdate);

/// Operation run at the end of an epoch
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// end-of-epoch-transaction-kind   =  eoe-change-epoch
///                                 =/ eoe-authenticator-state-create
///                                 =/ eoe-authenticator-state-expire
///                                 =/ eoe-randomness-state-create
///                                 =/ eoe-deny-list-state-create
///                                 =/ eoe-bridge-state-create
///                                 =/ eoe-bridge-committee-init
///                                 =/ eoe-store-execution-time-observations
///
/// eoe-change-epoch                = %x00 change-epoch
/// eoe-authenticator-state-create  = %x01
/// eoe-authenticator-state-expire  = %x02 authenticator-state-expire
/// eoe-randomness-state-create     = %x03
/// eoe-deny-list-state-create      = %x04
/// eoe-bridge-state-create         = %x05 digest
/// eoe-bridge-committee-init       = %x06 u64
/// eoe-store-execution-time-observations = %x07 stored-execution-time-observations
/// ```
#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct EndOfEpochTransactionKind(pub iota_types::EndOfEpochTransactionKind);

#[uniffi::export]
impl EndOfEpochTransactionKind {
    #[uniffi::constructor]
    pub fn change_epoch(tx: &ChangeEpoch) -> Self {
        Self(iota_types::EndOfEpochTransactionKind::ChangeEpoch(
            tx.0.clone(),
        ))
    }

    #[uniffi::constructor]
    pub fn change_epoch_v2(tx: &ChangeEpochV2) -> Self {
        Self(iota_types::EndOfEpochTransactionKind::ChangeEpochV2(
            tx.0.clone(),
        ))
    }

    #[uniffi::constructor]
    pub fn authenticator_state_create() -> Self {
        Self(iota_types::EndOfEpochTransactionKind::AuthenticatorStateCreate)
    }

    #[uniffi::constructor]
    pub fn authenticator_state_expire(tx: &AuthenticatorStateExpire) -> Self {
        Self(iota_types::EndOfEpochTransactionKind::AuthenticatorStateExpire(tx.0.clone()))
    }
}

/// Payment information for executing a transaction
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// gas-payment = (vector object-ref) ; gas coin objects
///               address             ; owner
///               u64                 ; price
///               u64                 ; budget
/// ```
#[derive(Clone, Debug, uniffi::Record)]
pub struct GasPayment {
    pub objects: Vec<ObjectReference>,
    pub owner: Arc<Address>,
    pub price: u64,
    pub budget: u64,
}

impl From<iota_types::GasPayment> for GasPayment {
    fn from(value: iota_types::GasPayment) -> Self {
        Self {
            objects: value.objects.into_iter().map(Into::into).collect(),
            owner: Arc::new(value.owner.into()),
            price: value.price,
            budget: value.budget,
        }
    }
}

impl From<GasPayment> for iota_types::GasPayment {
    fn from(value: GasPayment) -> Self {
        Self {
            objects: value.objects.into_iter().map(Into::into).collect(),
            owner: value.owner.0,
            price: value.price,
            budget: value.budget,
        }
    }
}

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct TransactionEffects(pub iota_types::TransactionEffects);

#[uniffi::export]
impl TransactionEffects {
    #[uniffi::constructor]
    pub fn new_v1(effects: TransactionEffectsV1) -> Self {
        Self(iota_types::TransactionEffects::V1(Box::new(effects.into())))
    }

    pub fn is_v1(&self) -> bool {
        matches!(self.0, iota_types::TransactionEffects::V1(_))
    }

    pub fn as_v1(&self) -> TransactionEffectsV1 {
        let iota_types::TransactionEffects::V1(inner) = self.0.clone();
        (*inner).into()
    }
}

#[uniffi::remote(Enum)]
pub enum TransactionExpiration {
    None,
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
/// argument-gas            = %x00
/// argument-input          = %x01 u16
/// argument-result         = %x02 u16
/// argument-nested-result  = %x03 u16 u16
/// ```
#[derive(Clone, Debug, PartialEq, Eq, derive_more::From, uniffi::Object)]
pub struct Argument(iota_types::Argument);

#[uniffi::export]
impl Argument {
    /// The gas coin. The gas coin can only be used by-ref, except for with
    /// `TransferObjects`, which can use it by-value.
    #[uniffi::constructor]
    pub fn new_gas() -> Self {
        Self(iota_types::Argument::Gas)
    }

    /// One of the input objects or primitive values (from
    /// `ProgrammableTransaction` inputs)
    #[uniffi::constructor]
    pub fn new_input(input: u16) -> Self {
        Self(iota_types::Argument::Input(input))
    }

    /// The result of another command (from `ProgrammableTransaction` commands)
    #[uniffi::constructor]
    pub fn new_result(result: u16) -> Self {
        Self(iota_types::Argument::Result(result))
    }

    /// Like a `Result` but it accesses a nested result. Currently, the only
    /// usage of this is to access a value from a Move call with multiple
    /// return values.
    // (command index, subresult index)
    #[uniffi::constructor]
    pub fn new_nested_result(command_index: u16, subresult_index: u16) -> Self {
        Self(iota_types::Argument::NestedResult(
            command_index,
            subresult_index,
        ))
    }

    /// Turn a Result into a NestedResult. If the argument is not a Result,
    /// returns None.
    pub fn nested(&self, ix: u16) -> Option<Arc<Argument>> {
        self.0.nested(ix).map(Self).map(Arc::new)
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
#[derive(Clone, Debug, PartialEq, Eq, derive_more::From, uniffi::Object)]
pub struct MoveCall(iota_types::MoveCall);

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
        Self(iota_types::MoveCall {
            package: package.0,
            module: module.0.clone(),
            function: function.0.clone(),
            type_arguments: type_arguments
                .iter()
                .map(|type_argument| type_argument.0.clone())
                .collect(),
            arguments: arguments
                .iter()
                .cloned()
                .map(|argument| argument.0)
                .collect(),
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
