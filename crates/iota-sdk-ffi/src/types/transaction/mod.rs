// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_types::{GasCostSummary, TransactionExpiration};

use crate::types::{
    address::Address,
    digest::{CheckpointDigest, TransactionDigest, TransactionEventsDigest},
    execution_status::ExecutionStatus,
    object::{ObjectId, ObjectReference},
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
    pub fn new(inputs: Vec<Input>, commands: Vec<Command>) -> Self {
        Self(iota_types::ProgrammableTransaction {
            inputs: inputs.iter().cloned().map(|input| input.0).collect(),
            commands,
        })
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
    pub fn new_merge_coins(merge_coins: MergeCoins) -> Self {}

    /// Publishes a Move package. It takes the package bytes and a list of the
    /// package's transitive dependencies to link against on-chain.
    #[uniffi::constructor]
    pub fn new_publish(publish: Publish) -> Self {}

    /// Given n-values of the same type, it constructs a vector. For non objects
    /// or an empty vector, the type tag must be specified.
    #[uniffi::constructor]
    pub fn new_make_move_vector(make_move_vector: MakeMoveVector) -> Self {}

    /// Upgrades a Move package
    /// Takes (in order):
    /// 1. A vector of serialized modules for the package.
    /// 2. A vector of object ids for the transitive dependencies of the new
    ///    package.
    /// 3. The object ID of the package being upgraded.
    /// 4. An argument holding the `UpgradeTicket` that must have been produced
    ///    from an earlier command in the same programmable transaction.
    #[uniffi::constructor]
    pub fn new_upgrade(upgrade: Upgrade) -> Self {}
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
            address: address.0.clone(),
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
            coin: coin.0.clone(),
            amounts: amounts.iter().map(|amount| amount.0.clone()).collect(),
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

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct ConsensusCommitPrologueV1(pub iota_types::ConsensusCommitPrologueV1);

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct GenesisTransaction(pub iota_types::GenesisTransaction);

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
            package: package.0.clone(),
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
