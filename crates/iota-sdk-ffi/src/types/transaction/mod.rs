// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_types::{GasCostSummary, TransactionExpiration};

use crate::types::{
    address::Address,
    digest::{CheckpointDigest, TransactionDigest, TransactionEventsDigest},
    execution_status::ExecutionStatus,
    object::ObjectReference,
    signature::UserSignature,
    transaction::v1::TransactionEffectsV1,
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
#[derive(Clone, Debug, uniffi::Record)]
pub struct Transaction {
    pub kind: Arc<TransactionKind>,
    pub sender: Arc<Address>,
    pub gas_payment: GasPayment,
    pub expiration: TransactionExpiration,
}

impl From<iota_types::Transaction> for Transaction {
    fn from(value: iota_types::Transaction) -> Self {
        Self {
            kind: Arc::new(value.kind.into()),
            sender: Arc::new(value.sender.into()),
            gas_payment: value.gas_payment.into(),
            expiration: value.expiration,
        }
    }
}

impl From<Transaction> for iota_types::Transaction {
    fn from(value: Transaction) -> Self {
        Self {
            kind: value.kind.0.clone(),
            sender: **value.sender,
            gas_payment: value.gas_payment.into(),
            expiration: value.expiration,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct SignedTransaction {
    pub transaction: Transaction,
    pub signatures: Vec<Arc<UserSignature>>,
}

impl From<iota_types::SignedTransaction> for SignedTransaction {
    fn from(value: iota_types::SignedTransaction) -> Self {
        Self {
            transaction: value.transaction.into(),
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
            transaction: value.transaction.into(),
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

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct ProgrammableTransaction(pub iota_types::ProgrammableTransaction);

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
    pub fn v1(effects: TransactionEffectsV1) -> Self {
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
