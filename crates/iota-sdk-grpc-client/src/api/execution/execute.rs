// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for transaction execution.

use iota_grpc_types::{
    read_mask_fields::{ExecuteTransactionReadMask, IntoReadMask},
    v1::{
        signatures::{UserSignature as ProtoUserSignature, UserSignatures},
        transaction::ExecutedTransaction,
        transaction_execution_service::{
            ExecuteTransactionItem, ExecuteTransactionsRequest,
            transaction_execution_service_client::TransactionExecutionServiceClient,
        },
    },
};
use iota_types::SignedTransaction;

use crate::{
    GrpcClient, InterceptedChannel,
    api::{
        GrpcError, GrpcResult, MetadataEnvelope, ProtocolError, build_proto_transaction,
        define_query, into_item_results,
    },
};

define_query! {
    /// Request for [`GrpcClient::execute_transaction`]. Await it to send the
    /// request.
    pub struct ExecuteTransactionQuery {
        batch: ExecuteTransactionsQuery,
    }
    output: GrpcResult<MetadataEnvelope<ExecutedTransaction>>;
}

impl ExecuteTransactionQuery {
    /// Wait up to `checkpoint_inclusion_timeout_ms` milliseconds for the
    /// transaction to be included in a checkpoint.
    pub fn checkpoint_inclusion_timeout_ms(
        mut self,
        checkpoint_inclusion_timeout_ms: impl Into<Option<u64>>,
    ) -> Self {
        self.batch = self
            .batch
            .checkpoint_inclusion_timeout_ms(checkpoint_inclusion_timeout_ms);
        self
    }

    /// Set the field mask controlling the returned fields.
    pub fn read_mask(mut self, read_mask: impl IntoReadMask<ExecuteTransactionReadMask>) -> Self {
        self.batch = self.batch.read_mask(read_mask);
        self
    }

    async fn send(self) -> GrpcResult<MetadataEnvelope<ExecutedTransaction>> {
        self.batch
            .send()
            .await?
            .try_map(extract_single_execution_result)
    }
}

define_query! {
    /// Request for [`GrpcClient::execute_transactions`]. Await it to send the
    /// request.
    pub struct ExecuteTransactionsQuery {
        service_client: TransactionExecutionServiceClient<InterceptedChannel>,
        transactions: Vec<SignedTransaction>,
        checkpoint_inclusion_timeout_ms: Option<u64>,
        read_mask: ExecuteTransactionReadMask,
    }
    output: GrpcResult<MetadataEnvelope<Vec<GrpcResult<ExecutedTransaction>>>>;
}

impl ExecuteTransactionsQuery {
    /// Wait up to `checkpoint_inclusion_timeout_ms` milliseconds for all
    /// executed transactions to be included in a checkpoint.
    pub fn checkpoint_inclusion_timeout_ms(
        mut self,
        checkpoint_inclusion_timeout_ms: impl Into<Option<u64>>,
    ) -> Self {
        self.checkpoint_inclusion_timeout_ms = checkpoint_inclusion_timeout_ms.into();
        self
    }

    /// Set the field mask controlling the returned fields.
    pub fn read_mask(mut self, read_mask: impl IntoReadMask<ExecuteTransactionReadMask>) -> Self {
        self.read_mask = read_mask.into_read_mask();
        self
    }

    async fn send(mut self) -> GrpcResult<MetadataEnvelope<Vec<GrpcResult<ExecutedTransaction>>>> {
        if self.transactions.is_empty() {
            return Err(GrpcError::EmptyRequest);
        }

        let items = self
            .transactions
            .into_iter()
            .map(build_execute_item)
            .collect::<GrpcResult<Vec<_>>>()?;

        let mut request = ExecuteTransactionsRequest::default()
            .with_transactions(items)
            .with_read_mask(self.read_mask);

        if let Some(timeout_ms) = self.checkpoint_inclusion_timeout_ms {
            request = request.with_checkpoint_inclusion_timeout_ms(timeout_ms);
        }

        let response = self.service_client.execute_transactions(request).await?;

        Ok(MetadataEnvelope::from(response).map(|r| into_item_results(r.transaction_results)))
    }
}

impl GrpcClient {
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
    /// Without [`read_mask`](ExecuteTransactionQuery::read_mask), the default
    /// mask is used. Pass a
    /// [`TransactionField`](iota_grpc_types::read_mask_fields::TransactionField)
    /// or any slice/array/vec of fields to choose the returned fields.
    ///
    /// # Checkpoint Inclusion
    ///
    /// If
    /// [`checkpoint_inclusion_timeout_ms`](ExecuteTransactionQuery::checkpoint_inclusion_timeout_ms)
    /// is set, the server will wait up to the specified duration (in
    /// milliseconds) for the transaction to be included in a checkpoint before
    /// returning. When set, include `checkpoint` and `timestamp` in the read
    /// mask to receive the data.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # use iota_types::SignedTransaction;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    ///
    /// let signed_tx: SignedTransaction = todo!();
    /// let result = client.execute_transaction(signed_tx).await?;
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
    pub fn execute_transaction(
        &self,
        signed_transaction: SignedTransaction,
    ) -> ExecuteTransactionQuery {
        ExecuteTransactionQuery {
            batch: self.execute_transactions(vec![signed_transaction]),
        }
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
    /// Without [`read_mask`](ExecuteTransactionsQuery::read_mask), the default
    /// mask is used for each `ExecutedTransaction`. Pass a
    /// [`TransactionField`](iota_grpc_types::read_mask_fields::TransactionField)
    /// or any slice/array/vec of fields to choose the returned fields.
    ///
    /// # Checkpoint Inclusion
    ///
    /// If
    /// [`checkpoint_inclusion_timeout_ms`](ExecuteTransactionsQuery::checkpoint_inclusion_timeout_ms)
    /// is set, the server will wait up to the specified duration (in
    /// milliseconds) for all executed transactions to be included in a
    /// checkpoint before returning. When set, include `checkpoint` and
    /// `timestamp` in the read mask to receive the data.
    ///
    /// # Errors
    ///
    /// Returns [`GrpcError::EmptyRequest`] if `transactions` is empty.
    /// Returns a transport-level [`GrpcError::Grpc`] if the entire RPC fails
    /// (e.g. batch size exceeded).
    pub fn execute_transactions(
        &self,
        transactions: Vec<SignedTransaction>,
    ) -> ExecuteTransactionsQuery {
        ExecuteTransactionsQuery {
            service_client: self.execution_service_client(),
            transactions,
            checkpoint_inclusion_timeout_ms: None,
            read_mask: ExecuteTransactionReadMask::default(),
        }
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

#[cfg(test)]
mod tests {
    use iota_grpc_types::read_mask_fields::{ExecuteTransactionReadMask, TransactionField};
    use iota_types::{
        Address, GasPayment, ProgrammableTransaction, SignedTransaction, Transaction,
        TransactionExpiration, TransactionKind, TransactionV1,
    };

    use crate::{GrpcClient, GrpcError};

    fn signed_transaction() -> SignedTransaction {
        SignedTransaction {
            transaction: Transaction::V1(TransactionV1 {
                kind: TransactionKind::Programmable(ProgrammableTransaction {
                    inputs: Vec::new(),
                    commands: Vec::new(),
                }),
                sender: Address::ZERO,
                gas_payment: GasPayment {
                    objects: Vec::new(),
                    owner: Address::ZERO,
                    price: 1,
                    budget: 1,
                },
                expiration: TransactionExpiration::None,
            }),
            signatures: Vec::new(),
        }
    }

    #[tokio::test]
    async fn execute_transaction_setters_reach_the_one_item_batch() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let query = client.execute_transaction(signed_transaction());
        assert_eq!(query.batch.transactions, vec![signed_transaction()]);
        assert_eq!(query.batch.checkpoint_inclusion_timeout_ms, None);
        assert_eq!(
            query.batch.read_mask.as_str(),
            ExecuteTransactionReadMask::default().as_str()
        );

        let query = query
            .checkpoint_inclusion_timeout_ms(5_000)
            .read_mask(TransactionField::EFFECTS);
        assert_eq!(query.batch.checkpoint_inclusion_timeout_ms, Some(5_000));
        assert_eq!(
            query.batch.read_mask.as_str(),
            ExecuteTransactionReadMask::from(TransactionField::EFFECTS).as_str()
        );
    }

    #[tokio::test]
    async fn awaiting_no_transactions_is_an_empty_request() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let result = client.execute_transactions(Vec::new()).await;
        assert!(matches!(result, Err(GrpcError::EmptyRequest)));
    }
}
