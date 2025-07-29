// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_types::{
    AuthenticatorStateExpire, AuthenticatorStateUpdateV1, ChangeEpoch, ChangeEpochV2,
    EndOfEpochData, ExecutionTimeObservations, RandomnessStateUpdate, TransactionExpiration,
    UserSignature,
};

use crate::types::{address::Address, digest::CheckpointDigest, object::ObjectReference};

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct Transaction(pub iota_types::Transaction);

#[uniffi::export]
impl Transaction {
    #[uniffi::constructor]
    pub fn new(
        kind: &TransactionKind,
        sender: &Address,
        gas_payment: &GasPayment,
        expiration: TransactionExpiration,
    ) -> Self {
        Self(iota_types::Transaction {
            kind: kind.0.clone(),
            sender: **sender,
            gas_payment: gas_payment.0.clone(),
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

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct SignedTransaction(pub iota_types::SignedTransaction);

#[uniffi::export]
impl SignedTransaction {
    #[uniffi::constructor]
    pub fn new(transaction: &Transaction, signatures: Vec<UserSignature>) -> Self {
        Self(iota_types::SignedTransaction {
            transaction: transaction.0.clone(),
            signatures,
        })
    }

    pub fn transaction(&self) -> Transaction {
        self.0.transaction.clone().into()
    }

    pub fn signatures(&self) -> Vec<UserSignature> {
        self.0.signatures.clone()
    }
}

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
    pub fn authenticator_state_update_v1(tx: AuthenticatorStateUpdateV1) -> Self {
        Self(iota_types::TransactionKind::AuthenticatorStateUpdateV1(tx))
    }

    #[uniffi::constructor]
    pub fn end_of_epoch(tx: Vec<Arc<EndOfEpochTransactionKind>>) -> Self {
        Self(iota_types::TransactionKind::EndOfEpoch(
            tx.into_iter().map(|tx| tx.0.clone()).collect(),
        ))
    }

    #[uniffi::constructor]
    pub fn randomness_state_update(tx: RandomnessStateUpdate) -> Self {
        Self(iota_types::TransactionKind::RandomnessStateUpdate(tx))
    }
}

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct ProgrammableTransaction(pub iota_types::ProgrammableTransaction);

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct ConsensusCommitPrologueV1(pub iota_types::ConsensusCommitPrologueV1);

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct EndOfEpochTransactionKind(pub iota_types::EndOfEpochTransactionKind);

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct GenesisTransaction(pub iota_types::GenesisTransaction);

#[uniffi::export]
impl EndOfEpochTransactionKind {
    #[uniffi::constructor]
    pub fn change_epoch(tx: ChangeEpoch) -> Self {
        Self(iota_types::EndOfEpochTransactionKind::ChangeEpoch(tx))
    }

    #[uniffi::constructor]
    pub fn change_epoch_v2(tx: ChangeEpochV2) -> Self {
        Self(iota_types::EndOfEpochTransactionKind::ChangeEpochV2(tx))
    }

    #[uniffi::constructor]
    pub fn authenticator_state_create() -> Self {
        Self(iota_types::EndOfEpochTransactionKind::AuthenticatorStateCreate)
    }

    #[uniffi::constructor]
    pub fn authenticator_state_expire(tx: AuthenticatorStateExpire) -> Self {
        Self(iota_types::EndOfEpochTransactionKind::AuthenticatorStateExpire(tx))
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
    pub fn store_execution_time_observations(obs: ExecutionTimeObservations) -> Self {
        Self(iota_types::EndOfEpochTransactionKind::StoreExecutionTimeObservations(obs))
    }
}

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct GasPayment(pub iota_types::GasPayment);

#[uniffi::export]
impl GasPayment {
    #[uniffi::constructor]
    pub fn new(
        objects: Vec<Arc<ObjectReference>>,
        owner: &Address,
        price: u64,
        budget: u64,
    ) -> Self {
        Self(iota_types::GasPayment {
            objects: objects.into_iter().map(|obj| obj.0.clone()).collect(),
            owner: todo!(),
            price,
            budget,
        })
    }
}

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct TransactionEffects(pub iota_types::TransactionEffects);
