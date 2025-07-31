// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::types::{
    address::Address, digest::CheckpointDigest, object::ObjectReference, signature::UserSignature,
};

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
        expiration: &TransactionExpiration,
    ) -> Self {
        Self(iota_types::Transaction {
            kind: kind.0.clone(),
            sender: **sender,
            gas_payment: gas_payment.into(),
            expiration: expiration.0.clone(),
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
        self.0.expiration.clone().into()
    }
}

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct SignedTransaction(pub iota_types::SignedTransaction);

#[uniffi::export]
impl SignedTransaction {
    #[uniffi::constructor]
    pub fn new(transaction: &Transaction, signatures: Vec<Arc<UserSignature>>) -> Self {
        Self(iota_types::SignedTransaction {
            transaction: transaction.0.clone(),
            signatures: signatures.into_iter().map(|s| s.0.clone()).collect(),
        })
    }

    pub fn transaction(&self) -> Transaction {
        self.0.transaction.clone().into()
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

    #[uniffi::constructor]
    pub fn bridge_state_create(chain_id: &CheckpointDigest) -> Self {
        Self(iota_types::EndOfEpochTransactionKind::BridgeStateCreate {
            chain_id: **chain_id,
        })
    }

    #[uniffi::constructor]
    pub fn bridge_committee_init(bridge_object_version: u64) -> Self {
        Self(iota_types::EndOfEpochTransactionKind::BridgeCommitteeInit {
            bridge_object_version,
        })
    }

    #[uniffi::constructor]
    pub fn store_execution_time_observations(obs: &ExecutionTimeObservations) -> Self {
        Self(iota_types::EndOfEpochTransactionKind::StoreExecutionTimeObservations(obs.0.clone()))
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
#[derive(Clone, Debug, derive_more::From, uniffi::Record)]
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

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct TransactionExpiration(pub iota_types::TransactionExpiration);
