// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Transaction execution API implementation.

use iota_sdk::grpc_client::read_mask_fields::ExecuteTransactionReadMask;

use crate::{
    error::Result,
    grpc::{api::ledger::transactions::ExecutedTransaction, client::GrpcClient},
    types::transaction::SignedTransaction,
};

/// The result of executing a single transaction in a batch: either the
/// executed transaction or an error.
#[derive(uniffi::Record)]
pub struct ExecutedTransactionResult {
    /// The executed transaction, if execution succeeded.
    pub transaction: Option<ExecutedTransaction>,
    /// The error message, if execution failed.
    pub error: Option<String>,
}

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
            .client()
            .execute_transaction(
                signed_transaction.into(),
                checkpoint_inclusion_timeout_ms,
                crate::grpc::api::read_mask::<ExecuteTransactionReadMask>(&read_mask),
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
        self.client()
            .execute_transactions(
                transactions.into_iter().map(Into::into).collect(),
                checkpoint_inclusion_timeout_ms,
                crate::grpc::api::read_mask::<ExecuteTransactionReadMask>(&read_mask),
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
}
