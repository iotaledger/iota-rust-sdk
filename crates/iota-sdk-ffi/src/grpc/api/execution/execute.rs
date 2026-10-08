// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Transaction execution API implementation.

use iota_sdk::grpc_client::read_mask_fields::ExecuteTransactionReadMask;

use crate::{
    error::Result,
    grpc::{
        api::ledger::transactions::{GrpcExecutedTransaction, GrpcExecutedTransactionResults},
        client::GrpcClient,
        read_mask_fields::GrpcTransactionField,
    },
    types::transaction::SignedTransaction,
};

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
            .checkpoint_inclusion_timeout_ms(checkpoint_inclusion_timeout_ms)
            .read_mask(crate::grpc::api::read_mask::<ExecuteTransactionReadMask, _>(read_mask))
            .await?
            .into_inner())
            .try_into()
    }

    /// Execute a batch of signed transactions.
    ///
    /// An error the server reports for one transaction does not abort the
    /// rest of the batch; reading that transaction's item throws the server's
    /// error message. A transaction the server returns but
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
    ) -> Result<GrpcExecutedTransactionResults> {
        GrpcExecutedTransactionResults::new(
            self.client()
                .execute_transactions(transactions.into_iter().map(Into::into).collect())
                .checkpoint_inclusion_timeout_ms(checkpoint_inclusion_timeout_ms)
                .read_mask(crate::grpc::api::read_mask::<ExecuteTransactionReadMask, _>(read_mask))
                .await?
                .into_inner(),
        )
    }
}
