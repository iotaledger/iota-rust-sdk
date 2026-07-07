// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for transaction queries.

use iota_grpc_types::{
    read_mask_fields::TransactionReadMask,
    v1::{
        ledger_service::{GetTransactionsRequest, TransactionRequest, TransactionRequests},
        transaction::ExecutedTransaction,
    },
};
use iota_types::TransactionDigest;

use crate::{
    Client,
    api::{
        Error, GET_TRANSACTIONS_READ_MASK, MetadataEnvelope, ProtoResult, Result, collect_stream,
        field_mask_with_default, saturating_usize_to_u32,
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
    /// Results are returned in the same order as the input digests.
    /// If a transaction is not found, an error is returned.
    ///
    /// The optional `read_mask` controls which fields the server returns; pass
    /// `None` for the default field mask [`GET_TRANSACTIONS_READ_MASK`], or a
    /// [`TransactionReadMask`](iota_grpc_types::read_mask_fields::TransactionReadMask)
    /// built from a
    /// [`TransactionField`](iota_grpc_types::read_mask_fields::TransactionField)
    /// or any slice/array/vec of fields.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyRequest`] if `digests` is empty.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::Client;
    /// # use iota_sdk_grpc_client::read_mask_fields::{TransactionField, TransactionReadMask};
    /// # use iota_types::TransactionDigest;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new_localnet()?;
    /// let digest: TransactionDigest = TransactionDigest::ZERO;
    ///
    /// // Default mask
    /// let txs = client.get_transactions([digest], None).await?;
    /// for tx in txs.body() {
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
    ///     .get_transactions(
    ///         [digest],
    ///         TransactionReadMask::from([TransactionField::EFFECTS, TransactionField::CHECKPOINT]),
    ///     )
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_transactions(
        &self,
        digests: impl IntoIterator<Item = TransactionDigest>,
        read_mask: impl Into<Option<TransactionReadMask>>,
    ) -> Result<MetadataEnvelope<Vec<ExecutedTransaction>>> {
        let requests = digests
            .into_iter()
            .map(|d| TransactionRequest::default().with_digest(d))
            .collect::<Vec<_>>();
        self.get_transactions_internal(requests, read_mask.into())
            .await
    }

    async fn get_transactions_internal(
        &self,
        requests: Vec<TransactionRequest>,
        read_mask: Option<TransactionReadMask>,
    ) -> Result<MetadataEnvelope<Vec<ExecutedTransaction>>> {
        if requests.is_empty() {
            return Err(Error::EmptyRequest);
        }

        let requests = TransactionRequests::default().with_requests(requests);

        let mut request = GetTransactionsRequest::default()
            .with_requests(requests)
            .with_read_mask(field_mask_with_default(
                read_mask.as_ref().map(|m| m.as_str()),
                GET_TRANSACTIONS_READ_MASK,
            ));

        if let Some(max_size) = self.max_decoding_message_size() {
            request = request.with_max_message_size_bytes(saturating_usize_to_u32(max_size));
        }

        let mut client = self.ledger_service_client();

        let response = client.get_transactions(request).await?;
        let (stream, metadata) = MetadataEnvelope::from(response).into_parts();

        // Server guarantees results are returned in request order
        collect_stream(stream, metadata, |msg| {
            let items = msg
                .transaction_results
                .into_iter()
                .map(|r| r.into_result())
                .collect::<Result<Vec<_>>>()?;
            Ok((msg.has_next, items))
        })
        .await
    }
}
