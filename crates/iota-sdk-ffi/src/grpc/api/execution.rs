// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Transaction execution API implementation.

use iota_sdk::grpc_client::read_mask_fields::{ExecuteTransactionReadMask, SimulateReadMask};

use crate::{
    error::Result,
    grpc::{
        client::GrpcClient,
        output_types::{
            ExecutedTransaction, ExecutedTransactionResult, SimulateTransactionInput,
            SimulatedTransaction, SimulatedTransactionResult,
        },
    },
    types::transaction::{SignedTransaction, Transaction},
};

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// Execute a signed transaction.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    /// If `None`, the transaction digest, effects, events, and input/output
    /// objects are returned.
    ///
    /// If `checkpoint_inclusion_timeout_ms` is provided, the server waits up
    /// to that long for the transaction to be included in a checkpoint
    /// before responding.
    #[uniffi::method(default(read_mask = None, checkpoint_inclusion_timeout_ms = None))]
    pub async fn execute_transaction(
        &self,
        signed_transaction: SignedTransaction,
        read_mask: Option<Vec<String>>,
        checkpoint_inclusion_timeout_ms: Option<u64>,
    ) -> Result<ExecutedTransaction> {
        (&self
            .0
            .read()
            .await
            .execute_transaction(
                signed_transaction.into(),
                checkpoint_inclusion_timeout_ms,
                super::read_mask::<ExecuteTransactionReadMask>(&read_mask),
            )
            .await?
            .into_inner())
            .try_into()
    }

    /// Execute a batch of signed transactions.
    ///
    /// A per-transaction error does not abort the rest of the batch; each
    /// result carries either the executed transaction or an error message.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    /// If `None`, the transaction digest, effects, events, and input/output
    /// objects are returned.
    ///
    /// If `checkpoint_inclusion_timeout_ms` is provided, the server waits up
    /// to that long for the transactions to be included in a checkpoint
    /// before responding.
    #[uniffi::method(default(read_mask = None, checkpoint_inclusion_timeout_ms = None))]
    pub async fn execute_transactions(
        &self,
        transactions: Vec<SignedTransaction>,
        read_mask: Option<Vec<String>>,
        checkpoint_inclusion_timeout_ms: Option<u64>,
    ) -> Result<Vec<ExecutedTransactionResult>> {
        self.0
            .read()
            .await
            .execute_transactions(
                transactions.into_iter().map(Into::into).collect(),
                checkpoint_inclusion_timeout_ms,
                super::read_mask::<ExecuteTransactionReadMask>(&read_mask),
            )
            .await?
            .into_inner()
            .into_iter()
            .map(|result| {
                Ok(match result {
                    Ok(transaction) => ExecutedTransactionResult {
                        transaction: Some((&transaction).try_into()?),
                        error: None,
                    },
                    Err(error) => ExecutedTransactionResult {
                        transaction: None,
                        error: Some(error.to_string()),
                    },
                })
            })
            .collect()
    }

    /// Simulate a transaction.
    ///
    /// If `skip_checks` is `true`, the VM checks are skipped during the
    /// simulation.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    #[uniffi::method(default(skip_checks = false, read_mask = None))]
    pub async fn simulate_transaction(
        &self,
        transaction: &Transaction,
        skip_checks: bool,
        read_mask: Option<Vec<String>>,
    ) -> Result<SimulatedTransaction> {
        (&self
            .0
            .read()
            .await
            .simulate_transaction(
                transaction.0.clone(),
                skip_checks,
                super::read_mask::<SimulateReadMask>(&read_mask),
            )
            .await?
            .into_inner())
            .try_into()
    }

    /// Simulate a batch of transactions.
    ///
    /// A per-transaction error does not abort the rest of the batch; each
    /// result carries either the simulated transaction or an error message.
    #[uniffi::method(default(read_mask = None))]
    pub async fn simulate_transactions(
        &self,
        transactions: Vec<SimulateTransactionInput>,
        read_mask: Option<Vec<String>>,
    ) -> Result<Vec<SimulatedTransactionResult>> {
        self.0
            .read()
            .await
            .simulate_transactions(
                transactions
                    .into_iter()
                    .map(|input| iota_sdk::grpc_client::SimulateTransactionInput {
                        transaction: input.transaction.0.clone(),
                        skip_checks: input.skip_checks,
                    })
                    .collect(),
                super::read_mask::<SimulateReadMask>(&read_mask),
            )
            .await?
            .into_inner()
            .into_iter()
            .map(|result| {
                Ok(match result {
                    Ok(transaction) => SimulatedTransactionResult {
                        transaction: Some((&transaction).try_into()?),
                        error: None,
                    },
                    Err(error) => SimulatedTransactionResult {
                        transaction: None,
                        error: Some(error.to_string()),
                    },
                })
            })
            .collect()
    }
}
