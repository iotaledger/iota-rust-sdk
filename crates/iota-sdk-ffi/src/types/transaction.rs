// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_types::{
    AuthenticatorStateExpire, AuthenticatorStateUpdateV1, ChangeEpoch, ChangeEpochV2,
    CheckpointDigest, ConsensusCommitPrologueV1, EndOfEpochData, ExecutionTimeObservations,
    GasPayment, GenesisTransaction, ProgrammableTransaction, RandomnessStateUpdate,
    TransactionExpiration, UserSignature,
};

use crate::types::address::Address;

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
            gas_payment,
            expiration,
        })
    }

    pub fn kind(&self) -> TransactionKind {
        TransactionKind(self.0.kind.clone())
    }

    pub fn sender(&self) -> Address {
        Address(self.0.sender)
    }

    pub fn gas_payment(&self) -> GasPayment {
        self.0.gas_payment.clone()
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
        Transaction(self.0.transaction.clone())
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
    pub fn programmable_transaction(tx: ProgrammableTransaction) -> Self {
        Self(iota_types::TransactionKind::ProgrammableTransaction(tx))
    }

    #[uniffi::constructor]
    pub fn genesis(tx: GenesisTransaction) -> Self {
        Self(iota_types::TransactionKind::Genesis(tx))
    }

    #[uniffi::constructor]
    pub fn consensus_commit_prologue_v1(tx: ConsensusCommitPrologueV1) -> Self {
        Self(iota_types::TransactionKind::ConsensusCommitPrologueV1(tx))
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
pub struct EndOfEpochTransactionKind(pub iota_types::EndOfEpochTransactionKind);

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
    pub fn bridge_state_create(chain_id: CheckpointDigest) -> Self {
        Self(iota_types::EndOfEpochTransactionKind::BridgeStateCreate { chain_id })
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
