// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_sdk::types::{
    ActiveJwk, AuthenticatorStateExpire, AuthenticatorStateUpdateV1, GasCostSummary, Jwk, JwkId,
    RandomnessStateUpdate, TransactionExpiration,
};

use crate::{
    base64_encode,
    error::Result,
    hex_encode,
    types::{
        address::Address,
        checkpoint::{CheckpointTimestamp, EpochId, ProtocolVersion},
        crypto::Bls12381PublicKey,
        digest::Digest,
        events::Event,
        execution_status::ExecutionStatus,
        object::{GenesisObject, ObjectId, ObjectReference, Version},
        signature::UserSignature,
        struct_tag::Identifier,
        transaction::v1::TransactionEffectsV1,
        type_tag::TypeTag,
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
/// transaction = %x00 transaction-v1
///
/// transaction-v1 = transaction-kind address gas-payment transaction-expiration
/// ```
#[derive(Clone, uniffi::Object)]
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

    pub fn digest(&self) -> Digest {
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
/// transaction = %x00 transaction-v1
///
/// transaction-v1 = transaction-kind address gas-payment transaction-expiration
/// ```
#[derive(derive_more::From, uniffi::Object)]
pub struct TransactionV1(pub iota_sdk::types::TransactionV1);

#[uniffi::export]
impl TransactionV1 {
    #[uniffi::constructor]
    pub fn new(
        kind: &TransactionKind,
        sender: &Address,
        gas_payment: GasPayment,
        expiration: TransactionExpiration,
    ) -> Self {
        Self(iota_sdk::types::TransactionV1 {
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

    pub fn digest(&self) -> Digest {
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

#[derive(uniffi::Record)]
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
#[derive(derive_more::From, uniffi::Object)]
pub struct TransactionKind(pub iota_sdk::types::TransactionKind);

#[uniffi::export]
impl TransactionKind {
    #[uniffi::constructor]
    pub fn new_programmable_transaction(tx: &ProgrammableTransaction) -> Self {
        Self(iota_sdk::types::TransactionKind::ProgrammableTransaction(
            tx.0.clone(),
        ))
    }

    #[uniffi::constructor]
    pub fn new_genesis(tx: &GenesisTransaction) -> Self {
        Self(iota_sdk::types::TransactionKind::Genesis(tx.0.clone()))
    }

    #[uniffi::constructor]
    pub fn new_consensus_commit_prologue_v1(tx: &ConsensusCommitPrologueV1) -> Self {
        Self(iota_sdk::types::TransactionKind::ConsensusCommitPrologueV1(
            tx.0.clone(),
        ))
    }

    #[uniffi::constructor]
    pub fn new_authenticator_state_update_v1(tx: &AuthenticatorStateUpdateV1) -> Self {
        Self(iota_sdk::types::TransactionKind::AuthenticatorStateUpdateV1(tx.clone()))
    }

    #[uniffi::constructor]
    pub fn new_end_of_epoch(tx: Vec<Arc<EndOfEpochTransactionKind>>) -> Self {
        Self(iota_sdk::types::TransactionKind::EndOfEpoch(
            tx.into_iter().map(|tx| tx.0.clone()).collect(),
        ))
    }

    #[uniffi::constructor]
    pub fn new_randomness_state_update(tx: &RandomnessStateUpdate) -> Self {
        Self(iota_sdk::types::TransactionKind::RandomnessStateUpdate(
            tx.clone(),
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
#[derive(derive_more::From, uniffi::Object)]
pub struct ProgrammableTransaction(pub iota_sdk::types::ProgrammableTransaction);

#[uniffi::export]
impl ProgrammableTransaction {
    #[uniffi::constructor]
    pub fn new(inputs: Vec<Arc<Input>>, commands: Vec<Arc<Command>>) -> Self {
        Self(iota_sdk::types::ProgrammableTransaction {
            inputs: inputs.iter().map(|input| input.0.clone()).collect(),
            commands: commands.iter().map(|command| command.0.clone()).collect(),
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
#[derive(derive_more::From, uniffi::Object)]
pub struct Input(pub iota_sdk::types::Input);

#[uniffi::export]
impl Input {
    /// For normal operations this is required to be a move primitive type and
    /// not contain structs or objects.
    #[uniffi::constructor]
    pub fn new_pure(value: Vec<u8>) -> Self {
        Self(iota_sdk::types::Input::Pure { value })
    }

    /// A move object that is either immutable or address owned
    #[uniffi::constructor]
    pub fn new_immutable_or_owned(object_ref: ObjectReference) -> Self {
        Self(iota_sdk::types::Input::ImmutableOrOwned(object_ref.into()))
    }

    /// A move object whose owner is "Shared"
    #[uniffi::constructor]
    pub fn new_shared(object_id: &ObjectId, initial_shared_version: u64, mutable: bool) -> Self {
        Self(iota_sdk::types::Input::Shared {
            object_id: object_id.0,
            initial_shared_version,
            mutable,
        })
    }

    #[uniffi::constructor]
    pub fn new_receiving(object_ref: ObjectReference) -> Self {
        Self(iota_sdk::types::Input::Receiving(object_ref.into()))
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
#[derive(derive_more::From, uniffi::Object)]
pub struct Command(pub iota_sdk::types::Command);

#[uniffi::export]
impl Command {
    /// A call to either an entry or a public Move function
    #[uniffi::constructor]
    pub fn new_move_call(move_call: &MoveCall) -> Self {
        Self(iota_sdk::types::Command::MoveCall(move_call.0.clone()))
    }

    /// It sends n-objects to the specified address. These objects must have
    /// store (public transfer) and either the previous owner must be an
    /// address or the object must be newly created.
    #[uniffi::constructor]
    pub fn new_transfer_objects(transfer_objects: &TransferObjects) -> Self {
        Self(iota_sdk::types::Command::TransferObjects(
            transfer_objects.0.clone(),
        ))
    }

    /// It splits off some amounts into a new coins with those amounts
    #[uniffi::constructor]
    pub fn new_split_coins(split_coins: &SplitCoins) -> Self {
        Self(iota_sdk::types::Command::SplitCoins(split_coins.0.clone()))
    }

    /// It merges n-coins into the first coin
    #[uniffi::constructor]
    pub fn new_merge_coins(merge_coins: &MergeCoins) -> Self {
        Self(iota_sdk::types::Command::MergeCoins(merge_coins.0.clone()))
    }

    /// Publishes a Move package. It takes the package bytes and a list of the
    /// package's transitive dependencies to link against on-chain.
    #[uniffi::constructor]
    pub fn new_publish(publish: &Publish) -> Self {
        Self(iota_sdk::types::Command::Publish(publish.0.clone()))
    }

    /// Given n-values of the same type, it constructs a vector. For non objects
    /// or an empty vector, the type tag must be specified.
    #[uniffi::constructor]
    pub fn new_make_move_vector(make_move_vector: &MakeMoveVector) -> Self {
        Self(iota_sdk::types::Command::MakeMoveVector(
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
        Self(iota_sdk::types::Command::Upgrade(upgrade.0.clone()))
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
#[derive(derive_more::From, uniffi::Object)]
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
#[derive(derive_more::From, uniffi::Object)]
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
#[derive(derive_more::From, uniffi::Object)]
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
#[derive(derive_more::From, uniffi::Object)]
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
#[derive(derive_more::From, uniffi::Object)]
pub struct MakeMoveVector(pub iota_sdk::types::MakeMoveVector);

#[uniffi::export]
impl MakeMoveVector {
    #[uniffi::constructor]
    pub fn new(type_tag: Option<Arc<TypeTag>>, elements: Vec<Arc<Argument>>) -> Self {
        Self(iota_sdk::types::MakeMoveVector {
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
#[derive(derive_more::From, uniffi::Object)]
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
#[derive(derive_more::From, uniffi::Object)]
pub struct ConsensusCommitPrologueV1(pub iota_sdk::types::ConsensusCommitPrologueV1);

#[uniffi::export]
impl ConsensusCommitPrologueV1 {
    #[uniffi::constructor]
    pub fn new(
        epoch: u64,
        round: u64,
        sub_dag_index: Option<u64>,
        commit_timestamp_ms: CheckpointTimestamp,
        consensus_commit_digest: &Digest,
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
    pub fn consensus_commit_digest(&self) -> Digest {
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

#[derive(derive_more::From, uniffi::Object)]
pub struct ConsensusDeterminedVersionAssignments(
    pub iota_sdk::types::ConsensusDeterminedVersionAssignments,
);

#[uniffi::export]
impl ConsensusDeterminedVersionAssignments {
    #[uniffi::constructor]
    pub fn new_cancelled_transactions(
        cancelled_transactions: Vec<Arc<CancelledTransaction>>,
    ) -> Self {
        Self(
            iota_sdk::types::ConsensusDeterminedVersionAssignments::CancelledTransactions {
                cancelled_transactions: cancelled_transactions
                    .into_iter()
                    .map(|v| v.0.clone())
                    .collect(),
            },
        )
    }

    pub fn is_cancelled_transactions(&self) -> bool {
        self.0.is_cancelled_transactions()
    }

    pub fn as_cancelled_transactions(&self) -> Vec<Arc<CancelledTransaction>> {
        self.0
            .as_cancelled_transactions()
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
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
#[derive(derive_more::From, uniffi::Object)]
pub struct CancelledTransaction(pub iota_sdk::types::CancelledTransaction);

#[uniffi::export]
impl CancelledTransaction {
    #[uniffi::constructor]
    pub fn new(digest: &Digest, version_assignments: Vec<Arc<VersionAssignment>>) -> Self {
        Self(iota_sdk::types::CancelledTransaction {
            digest: digest.0,
            version_assignments: version_assignments
                .into_iter()
                .map(|v| v.0.clone())
                .collect(),
        })
    }

    pub fn digest(&self) -> Digest {
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
#[derive(derive_more::From, uniffi::Object)]
pub struct VersionAssignment(iota_sdk::types::VersionAssignment);

#[uniffi::export]
impl VersionAssignment {
    #[uniffi::constructor]
    pub fn new(object_id: &ObjectId, version: u64) -> Self {
        Self(iota_sdk::types::VersionAssignment {
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
#[derive(derive_more::From, uniffi::Object)]
pub struct GenesisTransaction(iota_sdk::types::GenesisTransaction);

#[uniffi::export]
impl GenesisTransaction {
    #[uniffi::constructor]
    pub fn new(objects: Vec<Arc<GenesisObject>>, events: Vec<Event>) -> Self {
        Self(iota_sdk::types::GenesisTransaction {
            objects: objects.iter().map(|object| object.0.clone()).collect(),
            events: events.into_iter().map(Into::into).collect(),
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
#[derive(derive_more::From, uniffi::Object)]
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
#[derive(derive_more::From, uniffi::Object)]
pub struct SystemPackage(pub iota_sdk::types::SystemPackage);

#[uniffi::export]
impl SystemPackage {
    #[uniffi::constructor]
    pub fn new(version: Version, modules: Vec<Vec<u8>>, dependencies: Vec<Arc<ObjectId>>) -> Self {
        Self(iota_sdk::types::SystemPackage {
            version,
            modules,
            dependencies: dependencies.into_iter().map(|dep| dep.0).collect(),
        })
    }

    pub fn version(&self) -> Version {
        self.0.version
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
/// change-epoch = u64  ; next epoch
///                u64  ; protocol version
///                u64  ; storage charge
///                u64  ; computation charge
///                u64  ; computation charge burned
///                u64  ; storage rebate
///                u64  ; non-refundable storage fee
///                u64  ; epoch start timestamp
///                (vector system-package)
/// ```
#[derive(derive_more::From, uniffi::Object)]
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

#[derive(derive_more::From, uniffi::Object)]
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

/// Expire old JWKs
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// authenticator-state-expire = u64 u64
/// ```
#[uniffi::remote(Record)]
pub struct AuthenticatorStateExpire {
    /// Expire JWKs that have a lower epoch than this
    pub min_epoch: u64,
    /// The initial version of the authenticator object that it was shared at.
    pub authenticator_obj_initial_shared_version: u64,
}

/// Update the set of valid JWKs
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// authenticator-state-update = u64 ; epoch
///                              u64 ; round
///                              (vector active-jwk)
///                              u64 ; initial version of the authenticator object
/// ```
#[uniffi::remote(Record)]
pub struct AuthenticatorStateUpdateV1 {
    /// Epoch of the authenticator state update transaction
    pub epoch: u64,
    /// Consensus round of the authenticator state update
    pub round: u64,
    /// newly active jwks
    pub new_active_jwks: Vec<ActiveJwk>,
    pub authenticator_obj_initial_shared_version: u64,
}

/// A new Jwk
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// active-jwk = jwk-id jwk u64
/// ```
#[uniffi::remote(Record)]
pub struct ActiveJwk {
    /// Identifier used to uniquely identify a Jwk
    pub jwk_id: JwkId,
    /// The Jwk
    pub jwk: Jwk,
    /// Most recent epoch in which the jwk was validated
    pub epoch: u64,
}

/// Set of Execution Time Observations from the committee.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// stored-execution-time-observations =  %x00 v1-stored-execution-time-observations
///
/// v1-stored-execution-time-observations = (vec
///                                          execution-time-observation-key
///                                          (vec execution-time-observation)
///                                         )
/// ```
#[derive(derive_more::From, uniffi::Object)]
pub struct ExecutionTimeObservations(pub iota_sdk::types::ExecutionTimeObservations);

#[uniffi::export]
impl ExecutionTimeObservations {
    #[uniffi::constructor]
    pub fn new_v1(execution_time_observations: Vec<Arc<ExecutionTimeObservation>>) -> Self {
        Self(iota_sdk::types::ExecutionTimeObservations::V1(
            execution_time_observations
                .iter()
                .map(|obs| obs.0.clone())
                .collect(),
        ))
    }
}

#[derive(derive_more::From, uniffi::Object)]
pub struct ExecutionTimeObservation(pub iota_sdk::types::ExecutionTimeObservation);

#[uniffi::export]
impl ExecutionTimeObservation {
    #[uniffi::constructor]
    pub fn new(
        key: &ExecutionTimeObservationKey,
        observations: Vec<Arc<ValidatorExecutionTimeObservation>>,
    ) -> Self {
        Self(iota_sdk::types::ExecutionTimeObservation {
            key: key.0.clone(),
            observations: observations.into_iter().map(|obs| obs.0.clone()).collect(),
        })
    }

    pub fn key(&self) -> ExecutionTimeObservationKey {
        self.0.key.clone().into()
    }

    pub fn observations(&self) -> Vec<Arc<ValidatorExecutionTimeObservation>> {
        self.0
            .observations
            .iter()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }
}

/// An execution time observation from a particular validator
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// execution-time-observation = bls-public-key duration
/// duration =  u64 ; seconds
///             u32 ; subsecond nanoseconds
/// ```
#[derive(derive_more::From, uniffi::Object)]
pub struct ValidatorExecutionTimeObservation(iota_sdk::types::ValidatorExecutionTimeObservation);

#[uniffi::export]
impl ValidatorExecutionTimeObservation {
    #[uniffi::constructor]
    pub fn new(validator: &Bls12381PublicKey, duration: std::time::Duration) -> Self {
        Self(iota_sdk::types::ValidatorExecutionTimeObservation {
            validator: validator.0,
            duration,
        })
    }

    pub fn validator(&self) -> Bls12381PublicKey {
        self.0.validator.into()
    }

    pub fn duration(&self) -> std::time::Duration {
        self.0.duration
    }
}

/// Key for an execution time observation
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// execution-time-observation-key  =  %x00 move-entry-point
///                                 =/ %x01 ; transfer-objects
///                                 =/ %x02 ; split-coins
///                                 =/ %x03 ; merge-coins
///                                 =/ %x04 ; publish
///                                 =/ %x05 ; make-move-vec
///                                 =/ %x06 ; upgrade
///
/// move-entry-point = object-id string string (vec type-tag)
/// ```
#[derive(derive_more::From, uniffi::Object)]
pub struct ExecutionTimeObservationKey(iota_sdk::types::ExecutionTimeObservationKey);

#[uniffi::export]
impl ExecutionTimeObservationKey {
    #[uniffi::constructor]
    pub fn new_move_entry_point(
        package: Arc<ObjectId>,
        module: String,
        function: String,
        type_arguments: Vec<Arc<TypeTag>>,
    ) -> Self {
        Self(
            iota_sdk::types::ExecutionTimeObservationKey::MoveEntryPoint {
                package: package.0,
                module,
                function,
                type_arguments: type_arguments
                    .into_iter()
                    .map(|tag| tag.0.clone())
                    .collect(),
            },
        )
    }

    #[uniffi::constructor]
    pub fn new_transfer_objects() -> Self {
        Self(iota_sdk::types::ExecutionTimeObservationKey::TransferObjects)
    }

    #[uniffi::constructor]
    pub fn new_split_coins() -> Self {
        Self(iota_sdk::types::ExecutionTimeObservationKey::SplitCoins)
    }

    #[uniffi::constructor]
    pub fn new_merge_coins() -> Self {
        Self(iota_sdk::types::ExecutionTimeObservationKey::MergeCoins)
    }

    #[uniffi::constructor]
    pub fn new_publish() -> Self {
        Self(iota_sdk::types::ExecutionTimeObservationKey::Publish)
    }

    #[uniffi::constructor]
    pub fn new_make_move_vec() -> Self {
        Self(iota_sdk::types::ExecutionTimeObservationKey::MakeMoveVec)
    }

    #[uniffi::constructor]
    pub fn new_upgrade() -> Self {
        Self(iota_sdk::types::ExecutionTimeObservationKey::Upgrade)
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
#[uniffi::remote(Record)]
pub struct RandomnessStateUpdate {
    /// Epoch of the randomness state update transaction
    pub epoch: u64,
    /// Randomness round of the update
    pub randomness_round: u64,
    /// Updated random bytes
    pub random_bytes: Vec<u8>,
    /// The initial version of the randomness object that it was shared at
    pub randomness_obj_initial_shared_version: u64,
}

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
#[derive(derive_more::From, uniffi::Object)]
pub struct EndOfEpochTransactionKind(pub iota_sdk::types::EndOfEpochTransactionKind);

#[uniffi::export]
impl EndOfEpochTransactionKind {
    #[uniffi::constructor]
    pub fn new_change_epoch(tx: &ChangeEpoch) -> Self {
        Self(iota_sdk::types::EndOfEpochTransactionKind::ChangeEpoch(
            tx.0.clone(),
        ))
    }

    #[uniffi::constructor]
    pub fn new_change_epoch_v2(tx: &ChangeEpochV2) -> Self {
        Self(iota_sdk::types::EndOfEpochTransactionKind::ChangeEpochV2(
            tx.0.clone(),
        ))
    }

    #[uniffi::constructor]
    pub fn new_change_epoch_v3(tx: &ChangeEpochV3) -> Self {
        Self(iota_sdk::types::EndOfEpochTransactionKind::ChangeEpochV3(
            tx.0.clone(),
        ))
    }

    #[uniffi::constructor]
    pub fn new_authenticator_state_create() -> Self {
        Self(iota_sdk::types::EndOfEpochTransactionKind::AuthenticatorStateCreate)
    }

    #[uniffi::constructor]
    pub fn new_authenticator_state_expire(tx: &AuthenticatorStateExpire) -> Self {
        Self(iota_sdk::types::EndOfEpochTransactionKind::AuthenticatorStateExpire(tx.clone()))
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
#[derive(uniffi::Record)]
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
/// transaction-effects =  %x00 effects-v1
///                     =/ %x01 effects-v2
/// ```
#[derive(derive_more::From, uniffi::Object)]
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

    pub fn digest(&self) -> Digest {
        self.0.digest().into()
    }
}

/// A transaction argument used in programmable transactions.
#[derive(uniffi::Enum)]
pub enum TransactionArgument {
    /// Reference to the gas coin.
    GasCoin,
    /// An input to the programmable transaction block.
    Input {
        /// Index of the programmable transaction block input (0-indexed).
        ix: u32,
    },
    /// The result of another transaction command.
    Result {
        /// The index of the previous command (0-indexed) that returned this
        /// result.
        cmd: u32,
        /// If the previous command returns multiple values, this is the index
        /// of the individual result among the multiple results from
        /// that command (also 0-indexed).
        ix: Option<u32>,
    },
}

impl From<iota_sdk::types::TransactionArgument> for TransactionArgument {
    fn from(value: iota_sdk::types::TransactionArgument) -> Self {
        match value {
            iota_sdk::types::TransactionArgument::GasCoin => TransactionArgument::GasCoin,
            iota_sdk::types::TransactionArgument::Input { ix } => TransactionArgument::Input { ix },
            iota_sdk::types::TransactionArgument::Result { cmd, ix } => {
                TransactionArgument::Result { cmd, ix }
            }
        }
    }
}

impl From<TransactionArgument> for iota_sdk::types::TransactionArgument {
    fn from(value: TransactionArgument) -> Self {
        match value {
            TransactionArgument::GasCoin => iota_sdk::types::TransactionArgument::GasCoin,
            TransactionArgument::Input { ix } => iota_sdk::types::TransactionArgument::Input { ix },
            TransactionArgument::Result { cmd, ix } => {
                iota_sdk::types::TransactionArgument::Result { cmd, ix }
            }
        }
    }
}

/// A return value from a command in the dry run.
#[derive(uniffi::Record)]
pub struct DryRunReturn {
    /// The Move type of the return value.
    pub type_tag: Arc<TypeTag>,
    /// The BCS representation of the return value.
    pub bcs: Vec<u8>,
}

impl From<iota_sdk::types::DryRunReturn> for DryRunReturn {
    fn from(value: iota_sdk::types::DryRunReturn) -> Self {
        DryRunReturn {
            type_tag: Arc::new(value.type_tag.into()),
            bcs: value.bcs,
        }
    }
}

impl From<DryRunReturn> for iota_sdk::types::DryRunReturn {
    fn from(value: DryRunReturn) -> Self {
        iota_sdk::types::DryRunReturn {
            type_tag: value.type_tag.0.clone(),
            bcs: value.bcs,
        }
    }
}

/// A mutation to an argument that was mutably borrowed by a command.
#[derive(uniffi::Record)]
pub struct DryRunMutation {
    /// The transaction argument that was mutated.
    pub input: TransactionArgument,
    /// The Move type of the mutated value.
    pub type_tag: Arc<TypeTag>,
    /// The BCS representation of the mutated value.
    pub bcs: Vec<u8>,
}

impl From<iota_sdk::types::DryRunMutation> for DryRunMutation {
    fn from(value: iota_sdk::types::DryRunMutation) -> Self {
        DryRunMutation {
            input: value.input.into(),
            type_tag: Arc::new(value.type_tag.into()),
            bcs: value.bcs,
        }
    }
}

impl From<DryRunMutation> for iota_sdk::types::DryRunMutation {
    fn from(value: DryRunMutation) -> Self {
        iota_sdk::types::DryRunMutation {
            input: value.input.into(),
            type_tag: value.type_tag.0.clone(),
            bcs: value.bcs,
        }
    }
}

/// Effects of a single command in the dry run, including mutated references
/// and return values.
#[derive(uniffi::Record)]
pub struct DryRunEffect {
    /// Changes made to arguments that were mutably borrowed by this command.
    pub mutated_references: Vec<DryRunMutation>,
    /// Return results of this command.
    pub return_values: Vec<DryRunReturn>,
}

impl From<iota_sdk::types::DryRunEffect> for DryRunEffect {
    fn from(value: iota_sdk::types::DryRunEffect) -> Self {
        DryRunEffect {
            mutated_references: value
                .mutated_references
                .into_iter()
                .map(Into::into)
                .collect(),
            return_values: value.return_values.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<DryRunEffect> for iota_sdk::types::DryRunEffect {
    fn from(value: DryRunEffect) -> Self {
        iota_sdk::types::DryRunEffect {
            mutated_references: value
                .mutated_references
                .into_iter()
                .map(Into::into)
                .collect(),
            return_values: value.return_values.into_iter().map(Into::into).collect(),
        }
    }
}

/// The result of a simulation (dry run), which includes the effects of the
/// transaction, any errors that may have occurred, and intermediate results for
/// each command.
#[derive(uniffi::Record)]
pub struct DryRunResult {
    /// The error that occurred during dry run execution, if any.
    pub error: Option<String>,
    /// The intermediate results for each command of the dry run execution,
    /// including contents of mutated references and return values.
    pub results: Vec<DryRunEffect>,
    /// The transaction block representing the dry run execution.
    pub transaction: Option<SignedTransaction>,
    /// The effects of the transaction execution.
    pub effects: Option<Arc<TransactionEffects>>,
}

impl From<iota_sdk::types::DryRunResult> for DryRunResult {
    fn from(value: iota_sdk::types::DryRunResult) -> Self {
        DryRunResult {
            error: value.error,
            results: value.results.into_iter().map(Into::into).collect(),
            transaction: value.transaction.map(Into::into),
            effects: value.effects.map(Into::into).map(Arc::new),
        }
    }
}

impl From<DryRunResult> for iota_sdk::types::DryRunResult {
    fn from(value: DryRunResult) -> Self {
        iota_sdk::types::DryRunResult {
            error: value.error,
            results: value.results.into_iter().map(Into::into).collect(),
            transaction: value.transaction.map(Into::into),
            effects: value.effects.map(|v| v.0.clone()),
        }
    }
}

/// A TTL for a transaction
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// transaction-expiration =  %x00      ; none
///                        =/ %x01 u64  ; epoch
/// ```
#[uniffi::remote(Enum)]
pub enum TransactionExpiration {
    /// The transaction has no expiration
    None,
    /// Validators wont sign a transaction unless the expiration Epoch
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
/// argument-gas            = %x00
/// argument-input          = %x01 u16
/// argument-result         = %x02 u16
/// argument-nested-result  = %x03 u16 u16
/// ```
#[derive(derive_more::Deref, derive_more::From, uniffi::Object)]
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
#[derive(derive_more::From, uniffi::Object)]
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

crate::export_iota_types_objects_bcs_conversion!(
    Transaction,
    TransactionV1,
    TransactionKind,
    ProgrammableTransaction,
    Input,
    Command,
    TransferObjects,
    SplitCoins,
    MergeCoins,
    Publish,
    MakeMoveVector,
    Upgrade,
    ConsensusCommitPrologueV1,
    ConsensusDeterminedVersionAssignments,
    CancelledTransaction,
    VersionAssignment,
    GenesisTransaction,
    ChangeEpoch,
    SystemPackage,
    ChangeEpochV2,
    ExecutionTimeObservation,
    ExecutionTimeObservations,
    ValidatorExecutionTimeObservation,
    ExecutionTimeObservationKey,
    TransactionEffects,
    Argument,
    MoveCall,
);
crate::export_iota_types_bcs_conversion!(
    SignedTransaction,
    AuthenticatorStateExpire,
    AuthenticatorStateUpdateV1,
    ActiveJwk,
    RandomnessStateUpdate,
    GasPayment,
    TransactionExpiration,
);
