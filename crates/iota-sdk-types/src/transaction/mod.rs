// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::iter;

use itertools::Either;

use super::{
    Address, CheckpointTimestamp, Digest, EpochId, Event, GenesisObject, Identifier, Jwk, JwkId,
    ObjectId, ObjectReference, ProtocolVersion, TypeTag, UserSignature, Version,
};
use crate::crypto::RandomnessRound;

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization;
#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
pub(crate) use serialization::SignedTransactionWithIntentMessage;

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
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Transaction {
    #[cfg_attr(feature = "serde", serde(rename = "1"))]
    V1(TransactionV1),
    // When new variants are introduced, it is important that we check version support
    // in the validity_check function based on the protocol config.
}

impl Transaction {
    crate::def_is_as_into_opt!(V1(TransactionV1));
}

impl From<TransactionV1> for Transaction {
    fn from(v1: TransactionV1) -> Self {
        Transaction::V1(v1)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct TransactionV1 {
    pub kind: TransactionKind,
    pub sender: Address,
    pub gas_payment: GasPayment,
    pub expiration: TransactionExpiration,
}

#[cfg_attr(feature = "serde", derive(serde::Deserialize))]
pub struct SenderSignedTransaction(
    #[cfg_attr(
        feature = "serde",
        serde(with = "::serde_with::As::<crate::_serde::SignedTransactionWithIntentMessage>")
    )]
    pub SignedTransaction,
);

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct SignedTransaction {
    pub transaction: Transaction,
    pub signatures: Vec<UserSignature>,
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
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[non_exhaustive]
pub enum TransactionExpiration {
    /// The transaction has no expiration
    #[default]
    None,
    /// Validators won't sign a transaction unless the expiration Epoch
    /// is greater than or equal to the current epoch
    Epoch(EpochId),
}

impl TransactionExpiration {
    crate::def_is!(None);

    crate::def_is_as_into_opt!(Epoch(EpochId));
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct GasPayment {
    pub objects: Vec<ObjectReference>,
    /// Owner of the gas objects, either the transaction sender or a sponsor
    pub owner: Address,
    /// Gas unit price to use when charging for computation
    ///
    /// Must be greater-than-or-equal-to the network's current RGP (reference
    /// gas price)
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub price: u64,
    /// Total budget willing to spend for the execution of a transaction
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub budget: u64,
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct RandomnessStateUpdate {
    /// Epoch of the randomness state update transaction
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub epoch: u64,
    /// Randomness round of the update
    pub randomness_round: RandomnessRound,
    /// Updated random bytes
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::_serde::ReadableBase64Encoded")
    )]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::Base64"))]
    pub random_bytes: Vec<u8>,
    /// The initial version of the randomness object that it was shared at.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub randomness_obj_initial_shared_version: Version,
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[non_exhaustive]
pub enum TransactionKind {
    /// A user transaction comprised of a list of native commands and move calls
    ProgrammableTransaction(ProgrammableTransaction),
    /// Transaction used to initialize the chain state.
    ///
    /// Only valid if in the genesis checkpoint (0) and if this is the very
    /// first transaction ever executed on the chain.
    Genesis(GenesisTransaction),
    /// V1 consensus commit update
    ConsensusCommitPrologueV1(ConsensusCommitPrologueV1),
    /// Update set of valid JWKs used for zklogin
    AuthenticatorStateUpdateV1(AuthenticatorStateUpdateV1),
    /// Set of operations to run at the end of the epoch to close out the
    /// current epoch and start the next one.
    EndOfEpoch(Vec<EndOfEpochTransactionKind>),
    /// Randomness update
    RandomnessStateUpdate(RandomnessStateUpdate),
}

impl TransactionKind {
    crate::def_is_as_into_opt! {
        ProgrammableTransaction,
        ConsensusCommitPrologueV1,
        AuthenticatorStateUpdateV1,
        RandomnessStateUpdate,
    }

    crate::def_is_as_into_opt! {
        Genesis(GenesisTransaction),
        EndOfEpoch(Vec<EndOfEpochTransactionKind>),
    }
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "schemars",
    derive(schemars::JsonSchema),
    schemars(tag = "kind", rename_all = "snake_case")
)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[non_exhaustive]
pub enum EndOfEpochTransactionKind {
    /// End the epoch and start the next one
    ChangeEpoch(ChangeEpoch),
    /// End the epoch and start the next one
    ChangeEpochV2(ChangeEpochV2),
    /// End the epoch and start the next one
    ChangeEpochV3(ChangeEpochV3),
    /// End the epoch and start the next one
    ChangeEpochV4(ChangeEpochV4),
    // IMPORTANT: new enum variants should be added at the end to preserve serialization
    // compatibility. DO NOT CHANGE THE ORDER OF EXISTING ENTRIES!
    // AuthenticatorStateCreate and AuthenticatorStateExpire can be left at the end as long as
    // `enable_jwk_consensus_updates` is not enabled in the protocol config.
    /// Create and initialize the authenticator object used for zklogin
    AuthenticatorStateCreate,
    /// Expire JWKs used for zklogin
    AuthenticatorStateExpire(AuthenticatorStateExpire),
}

impl EndOfEpochTransactionKind {
    crate::def_is!(AuthenticatorStateCreate);

    crate::def_is_as_into_opt!(
        ChangeEpoch,
        ChangeEpochV2,
        ChangeEpochV3,
        ChangeEpochV4,
        AuthenticatorStateExpire
    );

    /// Creates a [`ChangeEpoch`] end-of-epoch transaction kind.
    #[allow(clippy::too_many_arguments)]
    pub fn new_change_epoch(
        next_epoch: EpochId,
        protocol_version: ProtocolVersion,
        storage_charge: u64,
        computation_charge: u64,
        storage_rebate: u64,
        non_refundable_storage_fee: u64,
        epoch_start_timestamp_ms: u64,
        system_packages: Vec<SystemPackage>,
    ) -> Self {
        Self::ChangeEpoch(ChangeEpoch {
            epoch: next_epoch,
            protocol_version,
            storage_charge,
            computation_charge,
            storage_rebate,
            non_refundable_storage_fee,
            epoch_start_timestamp_ms,
            system_packages,
        })
    }

    /// Creates a [`ChangeEpochV2`] end-of-epoch transaction kind.
    #[allow(clippy::too_many_arguments)]
    pub fn new_change_epoch_v2(
        next_epoch: EpochId,
        protocol_version: ProtocolVersion,
        storage_charge: u64,
        computation_charge: u64,
        computation_charge_burned: u64,
        storage_rebate: u64,
        non_refundable_storage_fee: u64,
        epoch_start_timestamp_ms: u64,
        system_packages: Vec<SystemPackage>,
    ) -> Self {
        Self::ChangeEpochV2(ChangeEpochV2 {
            epoch: next_epoch,
            protocol_version,
            storage_charge,
            computation_charge,
            computation_charge_burned,
            storage_rebate,
            non_refundable_storage_fee,
            epoch_start_timestamp_ms,
            system_packages,
        })
    }

    /// Creates a [`ChangeEpochV3`] end-of-epoch transaction kind.
    #[allow(clippy::too_many_arguments)]
    pub fn new_change_epoch_v3(
        next_epoch: EpochId,
        protocol_version: ProtocolVersion,
        storage_charge: u64,
        computation_charge: u64,
        computation_charge_burned: u64,
        storage_rebate: u64,
        non_refundable_storage_fee: u64,
        epoch_start_timestamp_ms: u64,
        system_packages: Vec<SystemPackage>,
        eligible_active_validators: Vec<u64>,
    ) -> Self {
        Self::ChangeEpochV3(ChangeEpochV3 {
            epoch: next_epoch,
            protocol_version,
            storage_charge,
            computation_charge,
            computation_charge_burned,
            storage_rebate,
            non_refundable_storage_fee,
            epoch_start_timestamp_ms,
            system_packages,
            eligible_active_validators,
        })
    }

    /// Creates a [`ChangeEpochV4`] end-of-epoch transaction kind.
    #[allow(clippy::too_many_arguments)]
    pub fn new_change_epoch_v4(
        next_epoch: EpochId,
        protocol_version: ProtocolVersion,
        storage_charge: u64,
        computation_charge: u64,
        computation_charge_burned: u64,
        storage_rebate: u64,
        non_refundable_storage_fee: u64,
        epoch_start_timestamp_ms: u64,
        system_packages: Vec<SystemPackage>,
        eligible_active_validators: Vec<u64>,
        scores: Vec<u64>,
        adjust_rewards_by_score: bool,
    ) -> Self {
        Self::ChangeEpochV4(ChangeEpochV4 {
            epoch: next_epoch,
            protocol_version,
            storage_charge,
            computation_charge,
            computation_charge_burned,
            storage_rebate,
            non_refundable_storage_fee,
            epoch_start_timestamp_ms,
            system_packages,
            eligible_active_validators,
            scores,
            adjust_rewards_by_score,
        })
    }

    /// Creates an [`AuthenticatorStateCreate`][Self::AuthenticatorStateCreate]
    /// end-of-epoch transaction kind.
    pub fn new_authenticator_state_create() -> Self {
        Self::AuthenticatorStateCreate
    }

    /// Creates an [`AuthenticatorStateExpire`] end-of-epoch transaction kind.
    pub fn new_authenticator_state_expire(
        min_epoch: u64,
        authenticator_obj_initial_shared_version: Version,
    ) -> Self {
        Self::AuthenticatorStateExpire(AuthenticatorStateExpire {
            min_epoch,
            authenticator_obj_initial_shared_version,
        })
    }

    /// Returns an iterator over the shared input objects required by this
    /// transaction kind.
    pub fn shared_input_objects(&self) -> impl Iterator<Item = SharedObjectReference> + '_ {
        match self {
            Self::ChangeEpoch(_)
            | Self::ChangeEpochV2(_)
            | Self::ChangeEpochV3(_)
            | Self::ChangeEpochV4(_) => {
                Either::Left(vec![SharedObjectReference::IOTA_SYSTEM_STATE_OBJ_MUTABLE].into_iter())
            }
            Self::AuthenticatorStateCreate => Either::Right(iter::empty()),
            Self::AuthenticatorStateExpire(expire) => Either::Left(
                vec![SharedObjectReference {
                    object_id: ObjectId::AUTHENTICATOR_STATE,
                    initial_shared_version: expire.authenticator_obj_initial_shared_version,
                    mutable: true,
                }]
                .into_iter(),
            ),
        }
    }
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
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum ExecutionTimeObservations {
    V1(Vec<ExecutionTimeObservation>),
}

impl ExecutionTimeObservations {
    crate::def_is_as_into_opt!(V1(Vec<ExecutionTimeObservation>));
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExecutionTimeObservation {
    pub key: ExecutionTimeObservationKey,
    pub observations: Vec<ValidatorExecutionTimeObservation>,
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
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ValidatorExecutionTimeObservation {
    pub validator: crate::Bls12381PublicKey,
    pub duration: std::time::Duration,
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
#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Clone)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[non_exhaustive]
pub enum ExecutionTimeObservationKey {
    // Contains all the fields from `ProgrammableMoveCall` besides `arguments`.
    MoveEntryPoint {
        /// The package containing the module and function.
        package: ObjectId,
        /// The specific module in the package containing the function.
        module: String,
        /// The function to be called.
        function: String,
        /// The type arguments to the function.
        /// NOTE: This field is currently not populated.
        type_arguments: Vec<TypeTag>,
    },
    TransferObjects,
    SplitCoins,
    MergeCoins,
    Publish, // special case: should not be used; we only use hard-coded estimate for this
    MakeMoveVec,
    Upgrade,
}

impl ExecutionTimeObservationKey {
    crate::def_is!(
        MoveEntryPoint,
        TransferObjects,
        SplitCoins,
        MergeCoins,
        Publish,
        MakeMoveVec,
        Upgrade,
    );
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct AuthenticatorStateExpire {
    /// expire JWKs that have a lower epoch than this
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub min_epoch: u64,
    /// The initial version of the authenticator object that it was shared at.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub authenticator_obj_initial_shared_version: Version,
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct AuthenticatorStateUpdateV1 {
    /// Epoch of the authenticator state update transaction
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub epoch: u64,
    /// Consensus round of the authenticator state update
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub round: u64,
    /// newly active jwks
    pub new_active_jwks: Vec<ActiveJwk>,
    /// The initial version of the authenticator object that it was shared at.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub authenticator_obj_initial_shared_version: Version,
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct ActiveJwk {
    /// Identifier used to uniquely identify a Jwk
    pub jwk_id: JwkId,
    /// The Jwk
    pub jwk: Jwk,
    /// Most recent epoch in which the jwk was validated
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub epoch: u64,
}

// This must match the sort order defined by jwk_lt in authenticator_state.move
impl PartialOrd for ActiveJwk {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// This must match the sort order defined by jwk_lt in authenticator_state.move
impl Ord for ActiveJwk {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        fn string_bytes_ord(a: &str, b: &str) -> std::cmp::Ordering {
            let a_bytes = a.as_bytes();
            let b_bytes = b.as_bytes();

            if a_bytes.len() < b_bytes.len() {
                return std::cmp::Ordering::Less;
            }
            if a_bytes.len() > b_bytes.len() {
                return std::cmp::Ordering::Greater;
            }

            for (a_byte, b_byte) in a_bytes.iter().zip(b_bytes.iter()) {
                if a_byte < b_byte {
                    return std::cmp::Ordering::Less;
                }
                if a_byte > b_byte {
                    return std::cmp::Ordering::Greater;
                }
            }

            std::cmp::Ordering::Equal
        }
        // note: epoch is ignored
        if self.jwk_id.iss != other.jwk_id.iss {
            string_bytes_ord(&self.jwk_id.iss, &other.jwk_id.iss)
        } else if self.jwk_id.kid != other.jwk_id.kid {
            string_bytes_ord(&self.jwk_id.kid, &other.jwk_id.kid)
        } else if self.jwk.kty != other.jwk.kty {
            string_bytes_ord(&self.jwk.kty, &other.jwk.kty)
        } else if self.jwk.e != other.jwk.e {
            string_bytes_ord(&self.jwk.e, &other.jwk.e)
        } else if self.jwk.n != other.jwk.n {
            string_bytes_ord(&self.jwk.n, &other.jwk.n)
        } else {
            string_bytes_ord(&self.jwk.alg, &other.jwk.alg)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[non_exhaustive]
pub enum ConsensusDeterminedVersionAssignments {
    /// Cancelled transaction version assignment.
    CancelledTransactions {
        #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=2).lift()))]
        cancelled_transactions: Vec<CancelledTransaction>,
    },
}

impl ConsensusDeterminedVersionAssignments {
    crate::def_is!(CancelledTransactions);

    pub fn as_cancelled_transactions(&self) -> &[CancelledTransaction] {
        let Self::CancelledTransactions {
            cancelled_transactions,
        } = self;
        cancelled_transactions
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct CancelledTransaction {
    pub digest: Digest,
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=2).lift()))]
    pub version_assignments: Vec<VersionAssignment>,
}

/// Object version assignment from consensus
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the
/// following ABNF:
///
/// ```text
/// version-assignment = object-id u64
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct VersionAssignment {
    pub object_id: ObjectId,
    pub version: Version,
}

impl VersionAssignment {
    /// Creates a [`VersionAssignment`].
    pub fn new(object_id: ObjectId, version: Version) -> Self {
        Self { object_id, version }
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct ConsensusCommitPrologueV1 {
    /// Epoch of the commit prologue transaction
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub epoch: u64,
    /// Consensus round of the commit
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub round: u64,
    /// The sub DAG index of the consensus commit. This field will be populated
    /// if there are multiple consensus commits per round.
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::_serde::OptionReadableDisplay")
    )]
    #[cfg_attr(feature = "schemars", schemars(with = "Option<crate::_schemars::U64>"))]
    pub sub_dag_index: Option<u64>,
    /// Unix timestamp from consensus
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub commit_timestamp_ms: CheckpointTimestamp,
    /// Digest of consensus output
    pub consensus_commit_digest: Digest,
    /// Stores consensus handler determined shared object version assignments.
    pub consensus_determined_version_assignments: ConsensusDeterminedVersionAssignments,
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct ChangeEpoch {
    /// The next (to become) epoch ID.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub epoch: EpochId,
    /// The protocol version in effect in the new epoch.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub protocol_version: ProtocolVersion,
    /// The total amount of gas charged for storage during the epoch.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub storage_charge: u64,
    /// The total amount of gas charged for computation during the epoch.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub computation_charge: u64,
    /// The amount of storage rebate refunded to the txn senders.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub storage_rebate: u64,
    /// The non-refundable storage fee.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub non_refundable_storage_fee: u64,
    /// Unix timestamp when epoch started
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub epoch_start_timestamp_ms: u64,
    /// System packages (specifically framework and move stdlib) that are
    /// written before the new epoch starts. This tracks framework upgrades
    /// on chain. When executing the ChangeEpoch txn, the validator must
    /// write out the modules below.  Modules are provided with the version they
    /// will be upgraded to, their modules in serialized form (which include
    /// their package ID), and a list of their transitive dependencies.
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=2).lift()))]
    pub system_packages: Vec<SystemPackage>,
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct ChangeEpochV2 {
    /// The next (to become) epoch ID.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub epoch: EpochId,
    /// The protocol version in effect in the new epoch.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub protocol_version: ProtocolVersion,
    /// The total amount of gas charged for storage during the epoch.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub storage_charge: u64,
    /// The total amount of gas charged for computation during the epoch.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub computation_charge: u64,
    /// The total amount of gas burned for computation during the epoch.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub computation_charge_burned: u64,
    /// The amount of storage rebate refunded to the txn senders.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub storage_rebate: u64,
    /// The non-refundable storage fee.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub non_refundable_storage_fee: u64,
    /// Unix timestamp when epoch started
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub epoch_start_timestamp_ms: u64,
    /// System packages (specifically framework and move stdlib) that are
    /// written before the new epoch starts. This tracks framework upgrades
    /// on chain. When executing the ChangeEpoch txn, the validator must
    /// write out the modules below.  Modules are provided with the version they
    /// will be upgraded to, their modules in serialized form (which include
    /// their package ID), and a list of their transitive dependencies.
    #[cfg_attr(test, any(proptest::collection::size_range(0..=2).lift()))]
    pub system_packages: Vec<SystemPackage>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct ChangeEpochV3 {
    /// The next (to become) epoch ID.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub epoch: EpochId,
    /// The protocol version in effect in the new epoch.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub protocol_version: ProtocolVersion,
    /// The total amount of gas charged for storage during the epoch.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub storage_charge: u64,
    /// The total amount of gas charged for computation during the epoch.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub computation_charge: u64,
    /// The total amount of gas burned for computation during the epoch.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub computation_charge_burned: u64,
    /// The amount of storage rebate refunded to the txn senders.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub storage_rebate: u64,
    /// The non-refundable storage fee.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub non_refundable_storage_fee: u64,
    /// Unix timestamp when epoch started
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub epoch_start_timestamp_ms: u64,
    /// System packages (specifically framework and move stdlib) that are
    /// written before the new epoch starts. This tracks framework upgrades
    /// on chain. When executing the ChangeEpoch txn, the validator must
    /// write out the modules below.  Modules are provided with the version they
    /// will be upgraded to, their modules in serialized form (which include
    /// their package ID), and a list of their transitive dependencies.
    #[cfg_attr(test, any(proptest::collection::size_range(0..=2).lift()))]
    pub system_packages: Vec<SystemPackage>,
    /// Vector of active validator indices eligible to take part in committee
    /// selection because they support the new, target protocol version.
    pub eligible_active_validators: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct ChangeEpochV4 {
    /// The next (to become) epoch ID.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub epoch: EpochId,
    /// The protocol version in effect in the new epoch.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub protocol_version: ProtocolVersion,
    /// The total amount of gas charged for storage during the epoch.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub storage_charge: u64,
    /// The total amount of gas charged for computation during the epoch.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub computation_charge: u64,
    /// The total amount of gas burned for computation during the epoch.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub computation_charge_burned: u64,
    /// The amount of storage rebate refunded to the txn senders.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub storage_rebate: u64,
    /// The non-refundable storage fee.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub non_refundable_storage_fee: u64,
    /// Unix timestamp when epoch started
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub epoch_start_timestamp_ms: u64,
    /// System packages (specifically framework and move stdlib) that are
    /// written before the new epoch starts. This tracks framework upgrades
    /// on chain. When executing the ChangeEpoch txn, the validator must
    /// write out the modules below.  Modules are provided with the version they
    /// will be upgraded to, their modules in serialized form (which include
    /// their package ID), and a list of their transitive dependencies.
    #[cfg_attr(test, any(proptest::collection::size_range(0..=2).lift()))]
    pub system_packages: Vec<SystemPackage>,
    /// Vector of active validator indices eligible to take part in committee
    /// selection because they support the new, target protocol version.
    pub eligible_active_validators: Vec<u64>,
    /// Vector of scores relative to the past epoch performance of each
    /// validator, ordered by the past epoch's validator index.
    pub scores: Vec<u64>,
    /// Whether to adjust validator rewards based on score.
    pub adjust_rewards_by_score: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct SystemPackage {
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub version: Version,
    #[cfg_attr(
        feature = "serde",
        serde(
            with = "::serde_with::As::<Vec<::serde_with::IfIsHumanReadable<crate::_serde::Base64Encoded, ::serde_with::Bytes>>>"
        )
    )]
    #[cfg_attr(feature = "schemars", schemars(with = "Vec<crate::_schemars::Base64>"))]
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=2).lift()))]
    pub modules: Vec<Vec<u8>>,
    pub dependencies: Vec<ObjectId>,
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct GenesisTransaction {
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=2).lift()))]
    pub objects: Vec<GenesisObject>,
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=10).lift()))]
    pub events: Vec<Event>,
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct ProgrammableTransaction {
    /// Input objects or primitive values
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=10).lift()))]
    pub inputs: Vec<Input>,
    /// The commands to be executed sequentially. A failure in any command will
    /// result in the failure of the entire transaction.
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=10).lift()))]
    pub commands: Vec<Command>,
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[non_exhaustive]
pub enum Input {
    /// A move value serialized as BCS.
    ///
    /// For normal operations this is required to be a move primitive type and
    /// not contain structs or objects.
    Pure(Vec<u8>),
    /// A move object that is either immutable or address owned
    ImmutableOrOwned(ObjectReference),
    /// A move object whose owner is "Shared"
    Shared(SharedObjectReference),
    /// A move object that is attempted to be received in this transaction.
    // TODO add discussion around what receiving is
    Receiving(ObjectReference),
}

impl Input {
    /// Shared `Input` for the IOTA system state object.
    pub const IOTA_SYSTEM_MUTABLE: Self = Self::Shared(SharedObjectReference {
        object_id: ObjectId::SYSTEM_STATE,
        initial_shared_version: Version::INITIAL_SHARED_VERSION,
        mutable: true,
    });

    /// Shared `Input` for the clock object.
    pub const CLOCK_IMMUTABLE: Self = Self::Shared(SharedObjectReference {
        object_id: ObjectId::CLOCK,
        initial_shared_version: Version::INITIAL_SHARED_VERSION,
        mutable: false,
    });

    /// Shared `Input` for the clock object.
    pub const CLOCK_MUTABLE: Self = Self::Shared(SharedObjectReference {
        object_id: ObjectId::CLOCK,
        initial_shared_version: Version::INITIAL_SHARED_VERSION,
        mutable: true,
    });

    crate::def_is_as_into_opt!(
        Pure(Vec<u8>),
        ImmutableOrOwned(ObjectReference),
        Shared(SharedObjectReference),
        Receiving(ObjectReference)
    );

    /// Create a `Pure` input from a BCS-serializable value.
    #[cfg(feature = "serde")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
    pub fn pure<T: serde::Serialize>(value: &T) -> Self {
        Self::Pure(bcs::to_bytes(value).expect("value should be serializable"))
    }

    /// Returns the object id referenced by this input, if any.
    ///
    /// Returns `None` for `Pure` inputs.
    pub fn object_id_opt(&self) -> Option<&ObjectId> {
        match self {
            Self::Pure { .. } => None,
            Self::ImmutableOrOwned(obj_ref) | Self::Receiving(obj_ref) => Some(&obj_ref.object_id),
            Self::Shared(SharedObjectReference { object_id, .. }) => Some(object_id),
        }
    }

    /// Returns `true` if this input references a mutable shared object.
    pub fn is_mutable_shared(&self) -> bool {
        matches!(
            self,
            Self::Shared(SharedObjectReference { mutable: true, .. })
        )
    }

    /// Returns the [`ObjectReference`] if this is an `ImmutableOrOwned` or
    /// `Receiving` input.
    pub fn as_object_ref_opt(&self) -> Option<&ObjectReference> {
        match self {
            Self::ImmutableOrOwned(obj_ref) | Self::Receiving(obj_ref) => Some(obj_ref),
            _ => None,
        }
    }

    /// Returns the pure value bytes if this is a `Pure` input.
    pub fn as_pure_value_opt(&self) -> Option<&[u8]> {
        match self {
            Self::Pure(value) => Some(value),
            _ => None,
        }
    }
}

/// A shared object input to a programmable transaction
#[derive(Copy, Clone, Hash, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct SharedObjectReference {
    pub object_id: ObjectId,
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    pub initial_shared_version: Version,
    /// Controls whether the caller asks for a mutable reference to the
    /// shared object.
    pub mutable: bool,
}

impl SharedObjectReference {
    pub const IOTA_SYSTEM_STATE_OBJ_MUTABLE: Self = Self {
        object_id: ObjectId::SYSTEM_STATE,
        initial_shared_version: Version::INITIAL_SHARED_VERSION,
        mutable: true,
    };

    /// Creates a new shared object reference from the object's id, initial
    /// shared version, and mutability.
    pub const fn new(object_id: ObjectId, initial_shared_version: Version, mutable: bool) -> Self {
        Self {
            object_id,
            initial_shared_version,
            mutable,
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
/// command-move-call           = %x00 move-call
/// command-transfer-objects    = %x01 transfer-objects
/// command-split-coins         = %x02 split-coins
/// command-merge-coins         = %x03 merge-coins
/// command-publish             = %x04 publish
/// command-make-move-vector    = %x05 make-move-vector
/// command-upgrade             = %x06 upgrade
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "schemars",
    derive(schemars::JsonSchema),
    schemars(tag = "command", rename_all = "snake_case")
)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[non_exhaustive]
pub enum Command {
    /// A call to either an entry or a public Move function
    MoveCall(MoveCall),
    /// `(Vec<forall T:key+store. T>, address)`
    /// It sends n-objects to the specified address. These objects must have
    /// store (public transfer) and either the previous owner must be an
    /// address or the object must be newly created.
    TransferObjects(TransferObjects),
    /// `(&mut Coin<T>, Vec<u64>)` -> `Vec<Coin<T>>`
    /// It splits off some amounts into a new coins with those amounts
    SplitCoins(SplitCoins),
    /// `(&mut Coin<T>, Vec<Coin<T>>)`
    /// It merges n-coins into the first coin
    MergeCoins(MergeCoins),
    /// Publishes a Move package. It takes the package bytes and a list of the
    /// package's transitive dependencies to link against on-chain.
    Publish(Publish),
    /// `forall T: Vec<T> -> vector<T>`
    /// Given n-values of the same type, it constructs a vector. For non objects
    /// or an empty vector, the type tag must be specified.
    MakeMoveVector(MakeMoveVector),
    /// Upgrades a Move package
    /// Takes (in order):
    /// 1. A vector of serialized modules for the package.
    /// 2. A vector of object ids for the transitive dependencies of the new
    ///    package.
    /// 3. The object ID of the package being upgraded.
    /// 4. An argument holding the `UpgradeTicket` that must have been produced
    ///    from an earlier command in the same programmable transaction.
    Upgrade(Upgrade),
}

impl Command {
    crate::def_is_as_into_opt!(
        MoveCall,
        TransferObjects,
        SplitCoins,
        MergeCoins,
        Publish,
        MakeMoveVector,
        Upgrade,
    );

    /// Create a command to call a Move function.
    pub fn new_move_call(
        package: ObjectId,
        module: Identifier,
        function: Identifier,
        type_arguments: Vec<TypeTag>,
        arguments: Vec<Argument>,
    ) -> Self {
        Command::MoveCall(MoveCall {
            package,
            module,
            function,
            type_arguments,
            arguments,
        })
    }

    /// Create a command to transfer objects to an address.
    pub fn new_transfer_objects(objects: Vec<Argument>, address: Argument) -> Self {
        Command::TransferObjects(TransferObjects { objects, address })
    }

    /// Create a command to split a coin into multiple coins by amounts.
    pub fn new_split_coins(coin: Argument, amounts: Vec<Argument>) -> Self {
        Command::SplitCoins(SplitCoins { coin, amounts })
    }

    /// Create a command to merge multiple coins into one.
    pub fn new_merge_coins(coin: Argument, coins_to_merge: Vec<Argument>) -> Self {
        Command::MergeCoins(MergeCoins {
            coin,
            coins_to_merge,
        })
    }

    /// Create a command to publish a new Move package.
    pub fn new_publish(modules: Vec<Vec<u8>>, dependencies: Vec<ObjectId>) -> Self {
        Command::Publish(Publish {
            modules,
            dependencies,
        })
    }

    /// Create a command to construct a Move vector from elements.
    pub fn new_make_move_vector(type_: Option<TypeTag>, elements: Vec<Argument>) -> Self {
        Command::MakeMoveVector(MakeMoveVector { type_, elements })
    }

    /// Create a command to upgrade an existing Move package.
    pub fn new_upgrade(
        modules: Vec<Vec<u8>>,
        dependencies: Vec<ObjectId>,
        package: ObjectId,
        ticket: Argument,
    ) -> Self {
        Command::Upgrade(Upgrade {
            modules,
            dependencies,
            package,
            ticket,
        })
    }
}

pub fn write_sep<T: core::fmt::Display>(
    f: &mut core::fmt::Formatter<'_>,
    items: impl IntoIterator<Item = T>,
    delimiters: Option<(&str, &str)>,
    sep: &str,
) -> std::fmt::Result {
    let mut xs = items.into_iter();
    let Some(x) = xs.next() else {
        return Ok(());
    };
    if let Some((l, _)) = delimiters {
        write!(f, "{l}")?;
    }
    write!(f, "{x}")?;
    for x in xs {
        write!(f, "{sep}{x}")?;
    }
    if let Some((_, r)) = delimiters {
        write!(f, "{r}")?;
    }
    Ok(())
}

impl core::fmt::Display for MoveCall {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            package,
            module,
            function,
            type_arguments,
            arguments,
        } = self;
        write!(f, "MoveCall(")?;
        write!(f, "{package}::{module}::{function}")?;
        if !type_arguments.is_empty() {
            write_sep(f, type_arguments, Some(("<", ">")), ",")?;
        }
        write_sep(f, arguments, Some(("(", ")")), ",")?;
        write!(f, ")")
    }
}

impl core::fmt::Display for TransferObjects {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { objects, address } = self;

        write!(f, "TransferObjects(")?;
        write_sep(f, objects, Some(("[", "]")), ",")?;
        write!(f, ",{address})")
    }
}

impl core::fmt::Display for SplitCoins {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { coin, amounts } = self;

        write!(f, "SplitCoins({coin},")?;
        write_sep(f, amounts, Some(("[", "]")), ",")?;
        write!(f, ")")
    }
}

impl core::fmt::Display for MergeCoins {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            coin,
            coins_to_merge,
        } = self;

        write!(f, "MergeCoins({coin},")?;
        write_sep(f, coins_to_merge, Some(("[", "]")), ",")?;
        write!(f, ")")
    }
}

impl core::fmt::Display for Publish {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { dependencies, .. } = self;

        write!(f, "Publish(_,")?;
        write_sep(f, dependencies, Some(("[", "]")), ",")?;
        write!(f, ")")
    }
}

impl core::fmt::Display for MakeMoveVector {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { type_, elements } = self;

        write!(f, "MakeMoveVector(")?;
        if let Some(ty) = type_ {
            write!(f, "Some({ty})")?;
        } else {
            write!(f, "None")?;
        }
        write!(f, ",")?;
        write_sep(f, elements, Some(("[", "]")), ",")?;
        write!(f, ")")
    }
}

impl core::fmt::Display for Upgrade {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            dependencies,
            package,
            ticket,
            ..
        } = self;

        write!(f, "Upgrade(_,")?;
        write_sep(f, dependencies, Some(("[", "]")), ",")?;
        write!(f, ", {package}")?;
        write!(f, ", {ticket}")?;
        write!(f, ")")
    }
}

impl core::fmt::Display for Command {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Command::MoveCall(cmd) => write!(f, "{cmd}"),
            Command::TransferObjects(cmd) => write!(f, "{cmd}"),
            Command::SplitCoins(cmd) => write!(f, "{cmd}"),
            Command::MergeCoins(cmd) => write!(f, "{cmd}"),
            Command::Publish(cmd) => write!(f, "{cmd}"),
            Command::MakeMoveVector(cmd) => write!(f, "{cmd}"),
            Command::Upgrade(cmd) => write!(f, "{cmd}"),
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct TransferObjects {
    /// Set of objects to transfer
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=2).lift()))]
    pub objects: Vec<Argument>,
    /// The address to transfer ownership to
    pub address: Argument,
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct SplitCoins {
    /// The coin to split
    pub coin: Argument,
    /// The amounts to split off
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=2).lift()))]
    pub amounts: Vec<Argument>,
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct MergeCoins {
    /// Coin to merge coins into
    pub coin: Argument,
    /// Set of coins to merge into `coin`
    ///
    /// All listed coins must be of the same type and be the same type as `coin`
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=2).lift()))]
    pub coins_to_merge: Vec<Argument>,
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct Publish {
    /// The serialized move modules
    #[cfg_attr(
        feature = "serde",
        serde(
            with = "::serde_with::As::<Vec<::serde_with::IfIsHumanReadable<crate::_serde::Base64Encoded, ::serde_with::Bytes>>>"
        )
    )]
    #[cfg_attr(feature = "schemars", schemars(with = "Vec<crate::_schemars::Base64>"))]
    pub modules: Vec<Vec<u8>>,
    /// Set of packages that the to-be published package depends on
    pub dependencies: Vec<ObjectId>,
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct MakeMoveVector {
    /// Type of the individual elements
    ///
    /// This is required to be set when the type can't be inferred, for example
    /// when the set of provided arguments are all pure input values.
    #[cfg_attr(feature = "serde", serde(rename = "type"))]
    pub type_: Option<TypeTag>,
    /// The set individual elements to build the vector with
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=2).lift()))]
    pub elements: Vec<Argument>,
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct Upgrade {
    /// The serialized move modules
    #[cfg_attr(
        feature = "serde",
        serde(
            with = "::serde_with::As::<Vec<::serde_with::IfIsHumanReadable<crate::_serde::Base64Encoded, ::serde_with::Bytes>>>"
        )
    )]
    #[cfg_attr(feature = "schemars", schemars(with = "Vec<crate::_schemars::Base64>"))]
    pub modules: Vec<Vec<u8>>,
    /// Set of packages that the to-be published package depends on
    pub dependencies: Vec<ObjectId>,
    /// Package id of the package to upgrade
    pub package: ObjectId,
    /// Ticket authorizing the upgrade
    pub ticket: Argument,
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
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[non_exhaustive]
pub enum Argument {
    /// The gas coin. The gas coin can only be used by-ref, except for with
    /// `TransferObjects`, which can use it by-value.
    Gas,
    /// One of the input objects or primitive values (from
    /// `ProgrammableTransaction` inputs)
    Input(u16),
    /// The result of another command (from `ProgrammableTransaction` commands)
    Result(u16),
    /// Like a `Result` but it accesses a nested result. Currently, the only
    /// usage of this is to access a value from a Move call with multiple
    /// return values.
    // (command index, subresult index)
    NestedResult(u16, u16),
}

impl std::fmt::Display for Argument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Argument::Gas => write!(f, "Gas"),
            Argument::Input(i) => write!(f, "Input({i})"),
            Argument::Result(i) => write!(f, "Result({i})"),
            Argument::NestedResult(i, j) => write!(f, "NestedResult({i},{j})"),
        }
    }
}

impl Argument {
    crate::def_is!(Gas, Input, Result, NestedResult);

    pub fn as_input_opt(&self) -> Option<u16> {
        if let Self::Input(idx) = self {
            Some(*idx)
        } else {
            None
        }
    }

    pub fn as_input(&self) -> u16 {
        self.as_input_opt().expect("not an input")
    }

    pub fn as_result_opt(&self) -> Option<u16> {
        if let Self::Result(idx) = self {
            Some(*idx)
        } else {
            None
        }
    }

    pub fn as_result(&self) -> u16 {
        self.as_result_opt().expect("not a result")
    }

    pub fn as_nested_result_opt(&self) -> Option<(u16, u16)> {
        if let Self::NestedResult(idx0, idx1) = self {
            Some((*idx0, *idx1))
        } else {
            None
        }
    }

    pub fn as_nested_result(&self) -> (u16, u16) {
        self.as_nested_result_opt().expect("not a nested result")
    }

    /// Get the nested result for this result at the given index. Returns None
    /// if this is not a Result.
    pub fn get_nested_result(&self, ix: u16) -> Option<Argument> {
        match self {
            Argument::Result(i) => Some(Argument::NestedResult(*i, ix)),
            _ => None,
        }
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct MoveCall {
    /// The package containing the module and function.
    pub package: ObjectId,
    /// The specific module in the package containing the function.
    #[cfg_attr(
        feature = "serde",
        serde(deserialize_with = "serialization::deserialize_ident_unchecked")
    )]
    pub module: Identifier,
    /// The function to be called.
    pub function: Identifier,
    /// The type arguments to the function.
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=2).lift()))]
    pub type_arguments: Vec<TypeTag>,
    /// The arguments to the function.
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=2).lift()))]
    pub arguments: Vec<Argument>,
}
