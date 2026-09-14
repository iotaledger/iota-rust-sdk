// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for transaction execution.

use iota_grpc_types::{
    read_mask_fields::{ExecuteTransactionReadMask, IntoReadMask},
    v1::{
        signatures::{UserSignature as ProtoUserSignature, UserSignatures},
        transaction::ExecutedTransaction,
        transaction_execution_service::{ExecuteTransactionItem, ExecuteTransactionsRequest},
    },
};
use iota_types::SignedTransaction;

use crate::{
    Client,
    api::{
        GrpcError, GrpcResult, MetadataEnvelope, ProtocolError, build_proto_transaction,
        into_item_results,
    },
};

impl Client {
    /// Execute a signed transaction.
    ///
    /// This submits the transaction to the network for execution and waits for
    /// the result. The transaction must be signed with valid signatures.
    ///
    /// Returns proto `ExecutedTransaction`. Use lazy conversion methods to
    /// extract data:
    /// - `result.effects()` - Get transaction effects
    /// - `result.events()` - Get transaction events (if available)
    /// - `result.input_objects()` - Get input objects (if requested)
    /// - `result.output_objects()` - Get output objects (if requested)
    /// - `result.balance_changes()` - Get balance changes (if requested)
    /// - `result.object_changes()` - Get object changes (if requested)
    ///
    /// The `read_mask` controls which fields the server returns; use
    /// `ExecuteTransactionReadMask::default()` for the default mask. Pass a
    /// [`TransactionField`](iota_grpc_types::read_mask_fields::TransactionField)
    /// or any slice/array/vec of fields — conversion is automatic.
    ///
    /// # Checkpoint Inclusion
    ///
    /// If `checkpoint_inclusion_timeout_ms` is set, the server will wait up to
    /// the specified duration (in milliseconds) for the transaction to be
    /// included in a checkpoint before returning. When set, include
    /// `checkpoint` and `timestamp` in the `read_mask` to receive the data.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::Client;
    /// # use iota_sdk_grpc_client::read_mask_fields::ExecuteTransactionReadMask;
    /// # use iota_types::SignedTransaction;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new_localnet()?;
    ///
    /// let signed_tx: SignedTransaction = todo!();
    /// let result = client
    ///     .execute_transaction(signed_tx, None, ExecuteTransactionReadMask::default())
    ///     .await?;
    ///
    /// let effects = result.body().effects()?.effects()?;
    /// println!("Status: {:?}", effects.as_v1().status);
    ///
    /// let events = result.body().events()?.events()?;
    /// if !events.0.is_empty() {
    ///     println!("Events: {}", events.0.len());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn execute_transaction(
        &self,
        signed_transaction: SignedTransaction,
        checkpoint_inclusion_timeout_ms: impl Into<Option<u64>>,
        read_mask: impl IntoReadMask<ExecuteTransactionReadMask>,
    ) -> GrpcResult<MetadataEnvelope<ExecutedTransaction>> {
        self.execute_transactions(
            vec![signed_transaction],
            checkpoint_inclusion_timeout_ms,
            read_mask,
        )
        .await?
        .try_map(extract_single_execution_result)
    }

    /// Execute a batch of signed transactions.
    ///
    /// Transactions are executed sequentially on the server. Each transaction
    /// is independent — failure of one does not abort the rest.
    ///
    /// Returns a `Vec<GrpcResult<ExecutedTransaction>>` in the same order as
    /// the input. Each element is either the successfully executed
    /// transaction or the per-item error returned by the server.
    ///
    /// The `read_mask` controls which fields the server returns for each
    /// `ExecutedTransaction`; use `ExecuteTransactionReadMask::default()` for
    /// the default mask. Pass a
    /// [`TransactionField`](iota_grpc_types::read_mask_fields::TransactionField)
    /// or any slice/array/vec of fields — conversion is automatic.
    ///
    /// # Checkpoint Inclusion
    ///
    /// If `checkpoint_inclusion_timeout_ms` is set, the server will wait up to
    /// the specified duration (in milliseconds) for all executed transactions
    /// to be included in a checkpoint before returning. When set, include
    /// `checkpoint` and `timestamp` in the `read_mask` to receive the data.
    ///
    /// # Errors
    ///
    /// Returns [`GrpcError::EmptyRequest`] if `transactions` is empty.
    /// Returns a transport-level [`GrpcError::Grpc`] if the entire RPC fails
    /// (e.g. batch size exceeded).
    pub async fn execute_transactions(
        &self,
        transactions: Vec<SignedTransaction>,
        checkpoint_inclusion_timeout_ms: impl Into<Option<u64>>,
        read_mask: impl IntoReadMask<ExecuteTransactionReadMask>,
    ) -> GrpcResult<MetadataEnvelope<Vec<GrpcResult<ExecutedTransaction>>>> {
        let read_mask = read_mask.into_read_mask();
        let checkpoint_inclusion_timeout_ms = checkpoint_inclusion_timeout_ms.into();
        if transactions.is_empty() {
            return Err(GrpcError::EmptyRequest);
        }

        let items = transactions
            .into_iter()
            .map(build_execute_item)
            .collect::<GrpcResult<Vec<_>>>()?;

        let mut request = ExecuteTransactionsRequest::default()
            .with_transactions(items)
            .with_read_mask(read_mask);

        if let Some(timeout_ms) = checkpoint_inclusion_timeout_ms {
            request = request.with_checkpoint_inclusion_timeout_ms(timeout_ms);
        }

        let response = self
            .execution_service_client()
            .execute_transactions(request)
            .await?;

        Ok(MetadataEnvelope::from(response).map(|r| into_item_results(r.transaction_results)))
    }
}

fn extract_single_execution_result(
    results: Vec<GrpcResult<ExecutedTransaction>>,
) -> GrpcResult<ExecutedTransaction> {
    results.into_iter().next().ok_or_else(|| {
        GrpcError::Protocol(ProtocolError::EmptyResponseField("transaction_results"))
    })?
}

/// Convert a `SignedTransaction` into a proto `ExecuteTransactionItem`.
fn build_execute_item(signed_transaction: SignedTransaction) -> GrpcResult<ExecuteTransactionItem> {
    let tx_digest = signed_transaction.transaction.digest();
    let proto_transaction = build_proto_transaction(&signed_transaction.transaction, tx_digest)?;

    let proto_signatures = UserSignatures::default().with_signatures(
        signed_transaction
            .signatures
            .into_iter()
            .map(|sig| ProtoUserSignature::try_from(sig).map_err(GrpcError::Signature))
            .collect::<GrpcResult<Vec<_>>>()?,
    );

    Ok(ExecuteTransactionItem::default()
        .with_transaction(proto_transaction)
        .with_signatures(proto_signatures))
}
