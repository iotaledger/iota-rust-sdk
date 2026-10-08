// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Transaction execution API implementation.

use iota_sdk::grpc_client::{
    ExecuteTransactionQuery, ExecuteTransactionsQuery, read_mask_fields::ExecuteTransactionReadMask,
};

use crate::{
    error::Result,
    grpc::{
        api::ledger::transactions::GrpcExecutedTransaction, client::GrpcClient,
        read_mask_fields::GrpcTransactionField,
    },
    helpers::SetIfSome,
    types::transaction::SignedTransaction,
};

/// The result of executing a single transaction in a batch: either the
/// executed transaction or an error.
#[derive(uniffi::Record)]
pub struct GrpcExecutedTransactionResult {
    /// The executed transaction, if execution succeeded.
    pub transaction: Option<GrpcExecutedTransaction>,
    /// The error message, if execution failed.
    pub error: Option<String>,
}

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// Execute a signed transaction.
    ///
    /// If `checkpoint_inclusion_timeout_ms` is provided, the server waits up
    /// to that long for the transaction to be included in a checkpoint
    /// before responding. Include `checkpoint` and `timestamp` in the
    /// `read_mask` to receive that data.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    /// If `None`, the transaction digest, effects, events, and input/output
    /// objects are returned.
    #[uniffi::method(default(checkpoint_inclusion_timeout_ms = None, read_mask = None))]
    pub async fn execute_transaction(
        &self,
        signed_transaction: SignedTransaction,
        checkpoint_inclusion_timeout_ms: Option<u64>,
        read_mask: Option<Vec<GrpcTransactionField>>,
    ) -> Result<GrpcExecutedTransaction> {
        (&self
            .client()
            .execute_transaction(signed_transaction.into())
            .set_if_some(
                checkpoint_inclusion_timeout_ms,
                ExecuteTransactionQuery::checkpoint_inclusion_timeout_ms,
            )
            .read_mask(crate::grpc::api::read_mask::<ExecuteTransactionReadMask, _>(read_mask))
            .await?
            .into_inner())
            .try_into()
    }

    /// Execute a batch of signed transactions.
    ///
    /// An error the server reports for one transaction does not abort the
    /// rest of the batch; each result carries either the executed transaction
    /// or the server's error message. A transaction the server returns but
    /// that cannot be decoded fails the whole call.
    ///
    /// If `checkpoint_inclusion_timeout_ms` is provided, the server waits up
    /// to that long for the transactions to be included in a checkpoint
    /// before responding. Include `checkpoint` and `timestamp` in the
    /// `read_mask` to receive that data.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    /// If `None`, the transaction digest, effects, events, and input/output
    /// objects are returned.
    #[uniffi::method(default(checkpoint_inclusion_timeout_ms = None, read_mask = None))]
    pub async fn execute_transactions(
        &self,
        transactions: Vec<SignedTransaction>,
        checkpoint_inclusion_timeout_ms: Option<u64>,
        read_mask: Option<Vec<GrpcTransactionField>>,
    ) -> Result<Vec<GrpcExecutedTransactionResult>> {
        self.client()
            .execute_transactions(transactions.into_iter().map(Into::into).collect())
            .set_if_some(
                checkpoint_inclusion_timeout_ms,
                ExecuteTransactionsQuery::checkpoint_inclusion_timeout_ms,
            )
            .read_mask(crate::grpc::api::read_mask::<ExecuteTransactionReadMask, _>(read_mask))
            .await?
            .into_inner()
            .into_iter()
            .map(|result| {
                Ok(match result {
                    Ok(transaction) => GrpcExecutedTransactionResult {
                        transaction: Some((&transaction).try_into()?),
                        error: None,
                    },
                    Err(error) => GrpcExecutedTransactionResult {
                        transaction: None,
                        error: Some(error.to_string()),
                    },
                })
            })
            .collect()
    }
}
