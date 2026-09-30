// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for transaction queries.

use iota_grpc_types::{
    read_mask_fields::{IntoReadMask, TransactionReadMask},
    v1::{
        ledger_service::{
            GetTransactionsRequest, TransactionRequest, TransactionRequests,
            ledger_service_client::LedgerServiceClient,
        },
        transaction::ExecutedTransaction,
    },
};
use iota_types::TransactionDigest;

use crate::{
    GrpcClient, InterceptedChannel,
    api::{
        GrpcError, GrpcResult, MetadataEnvelope, check_result_count, check_transaction_identity,
        collect_stream, define_query, into_item_results, saturating_usize_to_u32,
    },
};

define_query! {
    /// Request for [`GrpcClient::transactions`]. Await it to send the request.
    pub struct GetTransactionsQuery {
        service_client: LedgerServiceClient<InterceptedChannel>,
        max_message_size: Option<usize>,
        digests: Vec<TransactionDigest>,
        read_mask: TransactionReadMask,
    }
    output: GrpcResult<MetadataEnvelope<Vec<GrpcResult<ExecutedTransaction>>>>;
}

impl GetTransactionsQuery {
    /// Set the field mask controlling the returned fields.
    pub fn read_mask(mut self, read_mask: impl IntoReadMask<TransactionReadMask>) -> Self {
        self.read_mask = read_mask.into_read_mask();
        self
    }

    async fn send(mut self) -> GrpcResult<MetadataEnvelope<Vec<GrpcResult<ExecutedTransaction>>>> {
        if self.digests.is_empty() {
            return Err(GrpcError::EmptyRequest);
        }

        let requests = TransactionRequests::default().with_requests(
            self.digests
                .iter()
                .map(|d| TransactionRequest::default().with_digest(*d))
                .collect(),
        );

        let mut request = GetTransactionsRequest::default()
            .with_requests(requests)
            .with_read_mask(self.read_mask);

        if let Some(max_size) = self.max_message_size {
            request = request.with_max_message_size_bytes(saturating_usize_to_u32(max_size));
        }

        let response = self.service_client.get_transactions(request).await?;
        let (stream, metadata) = MetadataEnvelope::from(response).into_parts();

        // Server guarantees results are returned in request order
        let response = collect_stream(stream, metadata, |msg| {
            Ok((msg.has_next, into_item_results(msg.transaction_results)))
        })
        .await?;
        check_result_count(response.body(), self.digests.len())?;
        check_transaction_identity(response.body(), &self.digests)?;

        Ok(response)
    }
}

impl GrpcClient {
    /// Get transactions by their digests.
    ///
    /// Returns proto `ExecutedTransaction` for each transaction. Use the lazy
    /// conversion methods to extract data:
    /// - `tx.digest()` - Get transaction digest
    /// - `tx.transaction()` - Deserialize transaction
    /// - `tx.signatures()` - Deserialize signatures
    /// - `tx.effects()` - Deserialize effects
    /// - `tx.events()` - Deserialize events (if available)
    /// - `tx.checkpoint_sequence_number()` - Get checkpoint number
    /// - `tx.timestamp_ms()` - Get timestamp
    ///
    /// Results are returned in the same order as the input digests, one per
    /// digest.
    ///
    /// # Errors
    ///
    /// Returns [`GrpcError::EmptyRequest`] if `digests` is empty.
    ///
    /// Each digest gets its own result: a transaction the node does not have
    /// (never executed, or pruned) yields [`GrpcError::Server`] with code
    /// `NOT_FOUND` in that slot only, leaving the other transactions intact. A
    /// slot can also carry `FAILED_PRECONDITION` when the transaction itself is
    /// present but an object a requested field needs is gone, as described
    /// under Read Mask below. The outer `GrpcResult` is reserved for failures
    /// of the call itself, such as a transport error, and for a server that
    /// answered with a different number of results than digests requested
    /// ([`UnexpectedResultCount`]), which leaves no way to tell which digest
    /// each result belongs to, or answered a position with a different
    /// transaction than the one requested there ([`UnexpectedTransaction`]).
    /// The answered digest is read from the response or computed from the
    /// transaction's BCS, so a read mask that includes neither leaves nothing
    /// to check.
    ///
    /// [`UnexpectedResultCount`]: crate::ProtocolError::UnexpectedResultCount
    /// [`UnexpectedTransaction`]: crate::ProtocolError::UnexpectedTransaction
    ///
    /// # Read Mask
    ///
    /// Without [`read_mask`](GetTransactionsQuery::read_mask), the default
    /// mask is used. Pass a
    /// [`TransactionReadMask`](iota_grpc_types::read_mask_fields::TransactionReadMask)
    /// built from a
    /// [`TransactionField`](iota_grpc_types::read_mask_fields::TransactionField)
    /// or any slice/array/vec of fields to choose the returned fields.
    ///
    /// The `input_objects`, `output_objects`, `balance_changes` and
    /// `object_changes` fields (also included by wildcard masks) require the
    /// serving node to still have the transaction's objects. If one has been
    /// pruned, the transaction's result is a `FAILED_PRECONDITION` error
    /// instead of a silently incomplete answer — narrow the read mask, or
    /// fetch objects individually via
    /// [`objects`](GrpcClient::objects) for best-effort retrieval.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # use iota_sdk_grpc_client::read_mask_fields::{TransactionField, TransactionReadMask};
    /// # use iota_types::TransactionDigest;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    /// let digest: TransactionDigest = TransactionDigest::ZERO;
    ///
    /// // Default mask
    /// let txs = client.transactions([digest]).await?;
    /// for tx in txs.body() {
    ///     let tx = match tx {
    ///         Ok(tx) => tx,
    ///         // Only this digest failed; the remaining transactions are still
    ///         // usable
    ///         Err(e) => {
    ///             eprintln!("could not read transaction: {e}");
    ///             continue;
    ///         }
    ///     };
    ///
    ///     // Lazy conversion - only deserialize what you need
    ///     let effects = tx.effects()?.effects()?;
    ///     println!("Status: {:?}", effects.as_v1().status);
    ///
    ///     // Access checkpoint number
    ///     let checkpoint = tx.checkpoint_sequence_number()?;
    ///     println!("Checkpoint: {}", checkpoint);
    /// }
    ///
    /// // Selected fields
    /// let txs = client
    ///     .transactions([digest])
    ///     .read_mask(TransactionReadMask::from([
    ///         TransactionField::EFFECTS,
    ///         TransactionField::CHECKPOINT,
    ///     ]))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn transactions(
        &self,
        digests: impl IntoIterator<Item = TransactionDigest>,
    ) -> GetTransactionsQuery {
        GetTransactionsQuery {
            service_client: self.ledger_service_client(),
            max_message_size: self.max_decoding_message_size(),
            digests: digests.into_iter().collect(),
            read_mask: TransactionReadMask::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use iota_grpc_types::read_mask_fields::{TransactionField, TransactionReadMask};
    use iota_types::TransactionDigest;

    use crate::{GrpcClient, GrpcError};

    #[tokio::test]
    async fn read_mask_replaces_the_default_mask() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let query = client.transactions([TransactionDigest::ZERO]);
        assert_eq!(
            query.read_mask.as_str(),
            TransactionReadMask::default().as_str()
        );

        let query = query.read_mask(TransactionField::EFFECTS);
        assert_eq!(
            query.read_mask.as_str(),
            TransactionReadMask::from(TransactionField::EFFECTS).as_str()
        );
    }

    #[tokio::test]
    async fn awaiting_no_digests_is_an_empty_request() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let result = client.transactions(Vec::new()).await;
        assert!(matches!(result, Err(GrpcError::EmptyRequest)));
    }
}
