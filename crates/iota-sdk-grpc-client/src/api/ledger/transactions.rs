// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for transaction queries.

use iota_grpc_types::v1::{
    ledger_service::{GetTransactionsRequest, TransactionRequest, TransactionRequests},
    transaction::ExecutedTransaction,
};
use iota_types::TransactionDigest;

use crate::{
    Client,
    api::{
        Error, GET_TRANSACTIONS_READ_MASK, MetadataEnvelope, ReadMask, Result, check_result_count,
        collect_stream, field_mask_with_default, into_item_results, saturating_usize_to_u32,
    },
};

impl Client {
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
    /// Returns [`Error::EmptyRequest`] if `digests` is empty.
    ///
    /// Each digest gets its own result: a transaction the node does not have
    /// (never executed, or pruned) yields [`Error::Server`] with code
    /// `NOT_FOUND` in that slot only, leaving the other transactions intact. A
    /// slot can also carry `FAILED_PRECONDITION` when the transaction itself is
    /// present but an object a requested field needs is gone, as described
    /// under Read Mask below. The outer `Result` is reserved for failures
    /// of the call itself, such as a transport error, and for a server that
    /// answered with a different number of results than digests requested
    /// ([`UnexpectedResultCount`]), which leaves no way to tell which digest
    /// each result belongs to.
    ///
    /// [`UnexpectedResultCount`]: crate::ProtocolError::UnexpectedResultCount
    ///
    /// # Read Mask
    ///
    /// The optional `read_mask` parameter controls which fields the server
    /// returns. If `None`, uses [`GET_TRANSACTIONS_READ_MASK`].
    ///
    /// Use [`TransactionField`](iota_grpc_types::read_mask_fields::TransactionField)
    /// constants with [`ReadMask::from`] for field selection.
    ///
    /// The `input_objects`, `output_objects`, `balance_changes` and
    /// `object_changes` fields (also included by wildcard masks) require the
    /// serving node to still have the transaction's objects. If one has been
    /// pruned, the transaction's result is a `FAILED_PRECONDITION` error
    /// instead of a silently incomplete answer — narrow the read mask, or
    /// fetch objects individually via
    /// [`get_objects`](Client::get_objects) for best-effort retrieval.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::{Client, ReadMask};
    /// # use iota_sdk_grpc_client::read_mask_fields::TransactionField;
    /// # use iota_types::TransactionDigest;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("http://localhost:9000")?;
    /// let digest: TransactionDigest = todo!();
    ///
    /// // Get transactions with default mask
    /// let txs = client.get_transactions(&[digest], None).await?;
    ///
    /// // Get transactions with field mask
    /// let txs = client
    ///     .get_transactions(
    ///         &[digest],
    ///         Some(ReadMask::from(&[
    ///             TransactionField::EFFECTS,
    ///             TransactionField::CHECKPOINT,
    ///         ])),
    ///     )
    ///     .await?;
    ///
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
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_transactions(
        &self,
        digests: &[TransactionDigest],
        read_mask: Option<ReadMask<'_>>,
    ) -> Result<MetadataEnvelope<Vec<Result<ExecutedTransaction>>>> {
        if digests.is_empty() {
            return Err(Error::EmptyRequest);
        }

        let requests = TransactionRequests::default().with_requests(
            digests
                .iter()
                .map(|d| TransactionRequest::default().with_digest(*d))
                .collect(),
        );

        let mut request = GetTransactionsRequest::default()
            .with_requests(requests)
            .with_read_mask(field_mask_with_default(
                read_mask,
                GET_TRANSACTIONS_READ_MASK,
            ));

        if let Some(max_size) = self.max_decoding_message_size() {
            request = request.with_max_message_size_bytes(saturating_usize_to_u32(max_size));
        }

        let mut client = self.ledger_service_client();

        let response = client.get_transactions(request).await?;
        let (stream, metadata) = MetadataEnvelope::from(response).into_parts();

        // Server guarantees results are returned in request order
        let response = collect_stream(stream, metadata, |msg| {
            Ok((msg.has_next, into_item_results(msg.transaction_results)))
        })
        .await?;
        check_result_count(response.body(), digests.len())?;

        Ok(response)
    }
}
