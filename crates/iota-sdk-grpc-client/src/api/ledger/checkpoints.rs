// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for checkpoint queries.
//!
//! # Read Mask
//!
//! The checkpoint queries and streams take a mask through their `read_mask`
//! setter to control which data is included in the response. Without the
//! setter the default mask is used. Set a
//! [`CheckpointResponseField`](iota_grpc_types::read_mask_fields::CheckpointResponseField)
//! (or any slice/array/vec of fields) to choose the returned fields.

use std::pin::Pin;

use futures::{Stream, StreamExt};
use iota_grpc_types::{
    read_mask_fields::{CheckpointResponseReadMask, IntoReadMask},
    v1::{
        checkpoint, event, filter as grpc_filter,
        ledger_service::{
            GetCheckpointRequest, StreamCheckpointsRequest, checkpoint_data,
            get_checkpoint_request, ledger_service_client::LedgerServiceClient,
        },
        signatures::ValidatorAggregatedSignature as ProtoValidatorAggregatedSignature,
        transaction::ExecutedTransaction,
    },
};
use iota_types::{CheckpointDigest, CheckpointSequenceNumber};

use crate::{
    GrpcClient, GrpcError, InterceptedChannel,
    api::{
        CheckpointResponse, CheckpointStreamError, CheckpointStreamItem, GrpcResult,
        MetadataEnvelope, ProtocolError, TryFromProtoError, define_query, saturating_usize_to_u32,
    },
};

define_query! {
    /// Query for [`GrpcClient::checkpoint_latest`],
    /// [`GrpcClient::checkpoint_by_sequence_number`] and
    /// [`GrpcClient::checkpoint_by_digest`]. Await it to send the request.
    pub struct GetCheckpointQuery {
        service_client: LedgerServiceClient<InterceptedChannel>,
        max_message_size: Option<usize>,
        checkpoint_id: get_checkpoint_request::CheckpointId,
        transactions_filter: Option<grpc_filter::TransactionFilter>,
        events_filter: Option<grpc_filter::EventFilter>,
        read_mask: CheckpointResponseReadMask,
    }
    output: GrpcResult<MetadataEnvelope<CheckpointResponse>>;
}

impl GetCheckpointQuery {
    /// Set the filter to apply to transactions.
    ///
    /// The server rejects the call unless the read mask includes
    /// `TRANSACTIONS` or one of its sub-fields.
    pub fn transactions_filter(
        mut self,
        transactions_filter: grpc_filter::TransactionFilter,
    ) -> Self {
        self.transactions_filter = Some(transactions_filter);
        self
    }

    /// Set the filter to apply to events.
    ///
    /// The server rejects the call unless the read mask includes `EVENTS` or
    /// one of its sub-fields.
    pub fn events_filter(mut self, events_filter: grpc_filter::EventFilter) -> Self {
        self.events_filter = Some(events_filter);
        self
    }

    /// Set the field mask controlling the returned fields.
    pub fn read_mask(mut self, read_mask: impl IntoReadMask<CheckpointResponseReadMask>) -> Self {
        self.read_mask = read_mask.into_read_mask();
        self
    }

    fn into_request(
        self,
    ) -> GrpcResult<(
        LedgerServiceClient<InterceptedChannel>,
        GetCheckpointRequest,
    )> {
        let mut request = match self.checkpoint_id {
            get_checkpoint_request::CheckpointId::Latest(val) => {
                GetCheckpointRequest::default().with_latest(val)
            }
            get_checkpoint_request::CheckpointId::SequenceNumber(val) => {
                GetCheckpointRequest::default().with_sequence_number(val)
            }
            get_checkpoint_request::CheckpointId::Digest(val) => {
                GetCheckpointRequest::default().with_digest(val)
            }
            _ => {
                return Err(GrpcError::Protocol(ProtocolError::UnknownVariant(
                    "checkpoint ID",
                )));
            }
        }
        .with_read_mask(self.read_mask);

        if let Some(tf) = self.transactions_filter {
            request = request.with_transactions_filter(tf);
        }
        if let Some(ef) = self.events_filter {
            request = request.with_events_filter(ef);
        }
        if let Some(max_size) = self.max_message_size.map(saturating_usize_to_u32) {
            request = request.with_max_message_size_bytes(max_size);
        }

        Ok((self.service_client, request))
    }

    async fn send(self) -> GrpcResult<MetadataEnvelope<CheckpointResponse>> {
        let (mut service_client, request) = self.into_request()?;
        let response = service_client.get_checkpoint(request).await?;
        let (stream, metadata) = MetadataEnvelope::from(response).into_parts();

        let reassembled = GrpcClient::reassemble_checkpoint_data_stream(stream);
        futures::pin_mut!(reassembled);

        // Skip any progress messages and find the first checkpoint
        let checkpoint = loop {
            match reassembled.next().await {
                Some(Ok(CheckpointStreamItem::Checkpoint(cp))) => break *cp,
                Some(Ok(CheckpointStreamItem::Progress { .. })) => continue,
                Some(Err(e)) => return Err(e),
                None => {
                    return Err(TryFromProtoError::missing("checkpoint data").into());
                }
            }
        };

        Ok(MetadataEnvelope::new(checkpoint, metadata))
    }
}

type CheckpointStream = Pin<Box<dyn Stream<Item = GrpcResult<CheckpointResponse>> + Send>>;
type CheckpointItemStream = Pin<Box<dyn Stream<Item = GrpcResult<CheckpointStreamItem>> + Send>>;
type StreamCheckpointsCall = (
    LedgerServiceClient<InterceptedChannel>,
    StreamCheckpointsRequest,
);

struct CheckpointStreamOptions {
    service_client: LedgerServiceClient<InterceptedChannel>,
    max_message_size: Option<usize>,
    start_sequence_number: Option<CheckpointSequenceNumber>,
    end_sequence_number: Option<CheckpointSequenceNumber>,
    transactions_filter: Option<grpc_filter::TransactionFilter>,
    events_filter: Option<grpc_filter::EventFilter>,
    read_mask: CheckpointResponseReadMask,
}

impl CheckpointStreamOptions {
    async fn open(
        (mut service_client, request): StreamCheckpointsCall,
    ) -> GrpcResult<MetadataEnvelope<CheckpointItemStream>> {
        let response = service_client.stream_checkpoints(request).await?;
        let (stream, metadata) = MetadataEnvelope::from(response).into_parts();

        Ok(MetadataEnvelope::new(
            Box::pin(GrpcClient::reassemble_checkpoint_data_stream(stream)),
            metadata,
        ))
    }

    fn into_request(
        self,
        filter_checkpoints: bool,
        progress_interval_ms: Option<u32>,
    ) -> StreamCheckpointsCall {
        let mut request = StreamCheckpointsRequest::default().with_read_mask(self.read_mask);

        if let Some(start) = self.start_sequence_number {
            request = request.with_start_sequence_number(start);
        }
        if let Some(end) = self.end_sequence_number {
            request = request.with_end_sequence_number(end);
        }
        if let Some(tf) = self.transactions_filter {
            request = request.with_transactions_filter(tf);
        }
        if let Some(ef) = self.events_filter {
            request = request.with_events_filter(ef);
        }
        if filter_checkpoints {
            request = request.with_filter_checkpoints(true);
        }
        if let Some(ms) = progress_interval_ms {
            request = request.with_progress_interval_ms(ms);
        }
        if let Some(max_size) = self.max_message_size.map(saturating_usize_to_u32) {
            request = request.with_max_message_size_bytes(max_size);
        }

        (self.service_client, request)
    }
}

define_query! {
    /// Query for [`GrpcClient::checkpoints_stream`]. Await it to open the
    /// stream.
    pub struct CheckpointsStreamQuery {
        options: CheckpointStreamOptions,
    }
    output: GrpcResult<MetadataEnvelope<CheckpointStream>>;
}

impl CheckpointsStreamQuery {
    /// Set the first checkpoint to stream. Without it, starts from the
    /// latest checkpoint.
    pub fn start_sequence_number(
        mut self,
        start_sequence_number: CheckpointSequenceNumber,
    ) -> Self {
        self.options.start_sequence_number = Some(start_sequence_number);
        self
    }

    /// Set the last checkpoint to stream. Without it, streams indefinitely.
    pub fn end_sequence_number(mut self, end_sequence_number: CheckpointSequenceNumber) -> Self {
        self.options.end_sequence_number = Some(end_sequence_number);
        self
    }

    /// Set the filter to apply to transactions.
    ///
    /// The server rejects the call unless the read mask includes
    /// `TRANSACTIONS` or one of its sub-fields.
    pub fn transactions_filter(
        mut self,
        transactions_filter: grpc_filter::TransactionFilter,
    ) -> Self {
        self.options.transactions_filter = Some(transactions_filter);
        self
    }

    /// Set the filter to apply to events.
    ///
    /// The server rejects the call unless the read mask includes `EVENTS` or
    /// one of its sub-fields.
    pub fn events_filter(mut self, events_filter: grpc_filter::EventFilter) -> Self {
        self.options.events_filter = Some(events_filter);
        self
    }

    /// Set the field mask controlling the returned fields.
    pub fn read_mask(mut self, read_mask: impl IntoReadMask<CheckpointResponseReadMask>) -> Self {
        self.options.read_mask = read_mask.into_read_mask();
        self
    }

    fn into_request(self) -> StreamCheckpointsCall {
        self.options.into_request(false, None)
    }

    async fn send(self) -> GrpcResult<MetadataEnvelope<CheckpointStream>> {
        let (stream, metadata) = CheckpointStreamOptions::open(self.into_request())
            .await?
            .into_parts();

        // remove the wrapping CheckpointStreamItem layer since we know
        // filter_checkpoints is false and thus only Checkpoint items will be
        // produced
        let filtered = stream.filter_map(|item| async {
            match item {
                Ok(CheckpointStreamItem::Checkpoint(cp)) => Some(Ok(*cp)),
                Ok(CheckpointStreamItem::Progress { .. }) => None,
                Err(e) => Some(Err(e)),
            }
        });

        Ok(MetadataEnvelope::new(Box::pin(filtered), metadata))
    }
}

define_query! {
    /// Query for [`GrpcClient::checkpoints_stream_filtered`]. Await it to
    /// open the stream.
    pub struct CheckpointsStreamFilteredQuery {
        options: CheckpointStreamOptions,
        progress_interval_ms: Option<u32>,
    }
    output: GrpcResult<MetadataEnvelope<CheckpointItemStream>>;
}

impl CheckpointsStreamFilteredQuery {
    /// Set the first checkpoint to stream. Without it, starts from the
    /// latest checkpoint.
    pub fn start_sequence_number(
        mut self,
        start_sequence_number: CheckpointSequenceNumber,
    ) -> Self {
        self.options.start_sequence_number = Some(start_sequence_number);
        self
    }

    /// Set the last checkpoint to stream. Without it, streams indefinitely.
    pub fn end_sequence_number(mut self, end_sequence_number: CheckpointSequenceNumber) -> Self {
        self.options.end_sequence_number = Some(end_sequence_number);
        self
    }

    /// Set the filter to apply to transactions.
    ///
    /// The server rejects the call unless the read mask includes
    /// `TRANSACTIONS` or one of its sub-fields.
    pub fn transactions_filter(
        mut self,
        transactions_filter: grpc_filter::TransactionFilter,
    ) -> Self {
        self.options.transactions_filter = Some(transactions_filter);
        self
    }

    /// Set the filter to apply to events.
    ///
    /// The server rejects the call unless the read mask includes `EVENTS` or
    /// one of its sub-fields.
    pub fn events_filter(mut self, events_filter: grpc_filter::EventFilter) -> Self {
        self.options.events_filter = Some(events_filter);
        self
    }

    /// Set the field mask controlling the returned fields.
    pub fn read_mask(mut self, read_mask: impl IntoReadMask<CheckpointResponseReadMask>) -> Self {
        self.options.read_mask = read_mask.into_read_mask();
        self
    }

    /// Set the progress message interval in milliseconds. Defaults to
    /// 2000ms, minimum 500ms.
    pub fn progress_interval_ms(mut self, progress_interval_ms: u32) -> Self {
        self.progress_interval_ms = Some(progress_interval_ms);
        self
    }

    fn into_request(self) -> StreamCheckpointsCall {
        self.options.into_request(true, self.progress_interval_ms)
    }

    async fn send(self) -> GrpcResult<MetadataEnvelope<CheckpointItemStream>> {
        CheckpointStreamOptions::open(self.into_request()).await
    }
}

impl GrpcClient {
    /// Get the latest checkpoint.
    ///
    /// Returns the checkpoint with fields populated according to the read
    /// mask. Filter with
    /// [`transactions_filter`](GetCheckpointQuery::transactions_filter) and
    /// [`events_filter`](GetCheckpointQuery::events_filter), and choose the
    /// returned fields with [`read_mask`](GetCheckpointQuery::read_mask).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    /// let checkpoint = client.checkpoint_latest().await?;
    /// println!(
    ///     "Received checkpoint {}",
    ///     checkpoint.body().sequence_number()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn checkpoint_latest(&self) -> GetCheckpointQuery {
        self.checkpoint_query(get_checkpoint_request::CheckpointId::Latest(true))
    }

    /// Get checkpoint by sequence number.
    ///
    /// Returns the checkpoint with fields populated according to the read
    /// mask. Filter with
    /// [`transactions_filter`](GetCheckpointQuery::transactions_filter) and
    /// [`events_filter`](GetCheckpointQuery::events_filter), and choose the
    /// returned fields with [`read_mask`](GetCheckpointQuery::read_mask).
    ///
    /// # Parameters
    ///
    /// * `sequence_number` - The checkpoint sequence number to fetch
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    /// let checkpoint = client.checkpoint_by_sequence_number(100).await?;
    /// println!(
    ///     "Received checkpoint {}",
    ///     checkpoint.body().sequence_number()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn checkpoint_by_sequence_number(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> GetCheckpointQuery {
        self.checkpoint_query(get_checkpoint_request::CheckpointId::SequenceNumber(
            sequence_number,
        ))
    }

    /// Get checkpoint by digest.
    ///
    /// Returns the checkpoint with fields populated according to the read
    /// mask. Filter with
    /// [`transactions_filter`](GetCheckpointQuery::transactions_filter) and
    /// [`events_filter`](GetCheckpointQuery::events_filter), and choose the
    /// returned fields with [`read_mask`](GetCheckpointQuery::read_mask).
    ///
    /// # Parameters
    ///
    /// * `digest` - The checkpoint digest to fetch
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # use iota_types::CheckpointDigest;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    /// let digest: CheckpointDigest = todo!();
    /// let checkpoint = client.checkpoint_by_digest(digest).await?;
    /// println!(
    ///     "Received checkpoint {}",
    ///     checkpoint.body().sequence_number()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn checkpoint_by_digest(&self, digest: CheckpointDigest) -> GetCheckpointQuery {
        self.checkpoint_query(get_checkpoint_request::CheckpointId::Digest(digest.into()))
    }

    fn checkpoint_query(
        &self,
        checkpoint_id: get_checkpoint_request::CheckpointId,
    ) -> GetCheckpointQuery {
        GetCheckpointQuery {
            service_client: self.ledger_service_client(),
            max_message_size: self.max_decoding_message_size(),
            checkpoint_id,
            transactions_filter: None,
            events_filter: None,
            read_mask: CheckpointResponseReadMask::default(),
        }
    }

    /// Stream checkpoints across a range of checkpoints.
    ///
    /// Returns a stream of [`CheckpointResponse`] objects, each representing
    /// a complete checkpoint with its transactions and events. Every checkpoint
    /// in the range is yielded, even if the filters produce no matching
    /// transactions or events within it.
    ///
    /// To skip non-matching checkpoints entirely, use
    /// [`checkpoints_stream_filtered`](Self::checkpoints_stream_filtered).
    ///
    /// Without [`start_sequence_number`](CheckpointsStreamQuery::start_sequence_number)
    /// the stream starts from the latest checkpoint, and without
    /// [`end_sequence_number`](CheckpointsStreamQuery::end_sequence_number) it
    /// runs indefinitely. Filter with
    /// [`transactions_filter`](CheckpointsStreamQuery::transactions_filter) and
    /// [`events_filter`](CheckpointsStreamQuery::events_filter), and choose
    /// the returned fields with
    /// [`read_mask`](CheckpointsStreamQuery::read_mask).
    ///
    /// **Note:** The metadata in the returned [`MetadataEnvelope`] is captured
    /// from the initial gRPC response headers when the stream is opened. It is
    /// **not** updated as subsequent checkpoint data arrives.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # use futures::StreamExt;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    /// let mut stream = client
    ///     .checkpoints_stream()
    ///     .start_sequence_number(0)
    ///     .end_sequence_number(10)
    ///     .await?;
    ///
    /// while let Some(checkpoint) = stream.body_mut().next().await {
    ///     let checkpoint = checkpoint?;
    ///     println!("Received checkpoint {}", checkpoint.sequence_number());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn checkpoints_stream(&self) -> CheckpointsStreamQuery {
        CheckpointsStreamQuery {
            options: self.checkpoint_stream_options(),
        }
    }

    /// Stream checkpoints, skipping those with no matching data.
    ///
    /// Unlike [`checkpoints_stream`](Self::checkpoints_stream), this method
    /// sets `filter_checkpoints = true` on the server, which means checkpoints
    /// without any matching transactions or events are skipped entirely.
    ///
    /// The returned stream yields [`CheckpointStreamItem`], which is either a
    /// [`CheckpointStreamItem::Checkpoint`] or a
    /// [`CheckpointStreamItem::Progress`]. Progress messages are sent
    /// periodically during scanning to indicate liveness and the current scan
    /// position (default every 2 seconds, configurable via
    /// [`progress_interval_ms`](CheckpointsStreamFilteredQuery::progress_interval_ms)).
    ///
    /// For liveness detection, wrap `stream.next()` in
    /// `tokio::time::timeout()`: if neither a `Checkpoint` nor a `Progress`
    /// arrives within your chosen duration plus some buffer for connection
    /// latency, the connection is likely dead.
    ///
    /// At least one of
    /// [`transactions_filter`](CheckpointsStreamFilteredQuery::transactions_filter)
    /// or [`events_filter`](CheckpointsStreamFilteredQuery::events_filter) must
    /// be set. The range and the read mask work as for
    /// [`checkpoints_stream`](Self::checkpoints_stream).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::{GrpcClient, CheckpointStreamItem};
    /// # use iota_sdk_grpc_client::read_mask_fields::CheckpointResponseField;
    /// # use iota_grpc_types::v1::filter as grpc_filter;
    /// # use futures::StreamExt;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    /// // At least one filter is required
    /// let tx_filter = grpc_filter::TransactionFilter::default()
    ///     .with_execution_status(grpc_filter::ExecutionStatusFilter::default().with_success(true));
    /// let mut stream = client
    ///     .checkpoints_stream_filtered()
    ///     .start_sequence_number(0)
    ///     .transactions_filter(tx_filter)
    ///     // A transactions filter requires transactions in the read mask
    ///     .read_mask([
    ///         CheckpointResponseField::CHECKPOINT_SUMMARY,
    ///         CheckpointResponseField::TRANSACTIONS,
    ///     ])
    ///     .await?;
    ///
    /// while let Some(item) = stream.body_mut().next().await {
    ///     match item? {
    ///         CheckpointStreamItem::Checkpoint(cp) => {
    ///             println!("Matched checkpoint {}", cp.sequence_number());
    ///         }
    ///         CheckpointStreamItem::Progress {
    ///             latest_scanned_sequence_number,
    ///         } => {
    ///             println!("Scanned up to {latest_scanned_sequence_number}");
    ///         }
    ///         _ => {}
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn checkpoints_stream_filtered(&self) -> CheckpointsStreamFilteredQuery {
        CheckpointsStreamFilteredQuery {
            options: self.checkpoint_stream_options(),
            progress_interval_ms: None,
        }
    }

    fn checkpoint_stream_options(&self) -> CheckpointStreamOptions {
        CheckpointStreamOptions {
            service_client: self.ledger_service_client(),
            max_message_size: self.max_decoding_message_size(),
            start_sequence_number: None,
            end_sequence_number: None,
            transactions_filter: None,
            events_filter: None,
            read_mask: CheckpointResponseReadMask::default(),
        }
    }

    /// Reassemble a stream of checkpoint data chunks into complete checkpoints.
    ///
    /// The server sends checkpoint data in multiple messages:
    /// - `Checkpoint` - Contains the checkpoint summary and contents
    /// - `Transactions` - Contains executed transactions
    /// - `Events` - Contains events from transactions
    /// - `Progress` - Liveness indicator during filtered scanning
    /// - `EndMarker` - Signals the end of one checkpoint's data
    ///
    /// This function buffers the chunks and yields [`CheckpointStreamItem`]
    /// values: either complete [`CheckpointResponse`] objects when an
    /// `EndMarker` is received, or [`CheckpointStreamItem::Progress`] when
    /// a progress message arrives.
    fn reassemble_checkpoint_data_stream<S, E>(
        stream: S,
    ) -> impl Stream<Item = GrpcResult<CheckpointStreamItem>>
    where
        S: Stream<
            Item = std::result::Result<iota_grpc_types::v1::ledger_service::CheckpointData, E>,
        >,
        E: Into<GrpcError>,
    {
        async_stream::try_stream! {
            futures::pin_mut!(stream);

            // State for accumulating checkpoint data
            let mut current_sequence_number: Option<CheckpointSequenceNumber> = None;
            let mut current_summary: Option<checkpoint::CheckpointSummary> = None;
            let mut current_signature: Option<ProtoValidatorAggregatedSignature> = None;
            let mut current_contents: Option<checkpoint::CheckpointContents> = None;
            let mut current_transactions: Vec<ExecutedTransaction> = Vec::new();
            let mut current_events: Vec<event::Event> = Vec::new();

            while let Some(data) = stream.next().await {
                let data = data.map_err(|e| e.into())?;

                match data.payload {
                    Some(checkpoint_data::Payload::Checkpoint(checkpoint)) => {
                        if checkpoint.sequence_number.is_none() {
                            Err(TryFromProtoError::missing("checkpoint.sequence_number"))?;
                        }

                        // Start of new checkpoint - throw error if previous checkpoint was incomplete
                        if current_sequence_number.is_some() {
                            Err(GrpcError::Protocol(CheckpointStreamError::IncompleteCheckpoint.into()))?;
                        }
                        current_sequence_number = checkpoint.sequence_number;

                        // Store proto summary (optional, no deserialization)
                        current_summary = checkpoint.summary;

                        // Store proto signature (optional, no deserialization)
                        current_signature = checkpoint.signature;

                        // Store proto contents (optional, no deserialization)
                        current_contents = checkpoint.contents;

                        // Reset accumulators for new checkpoint (in case Transactions or Events
                        // arrived between endmarker and Checkpoint)
                        current_transactions.clear();
                        current_events.clear();
                    }

                    Some(checkpoint_data::Payload::ExecutedTransactions(txs)) => {
                        if current_sequence_number.is_none() {
                            Err(GrpcError::Protocol(CheckpointStreamError::DataBeforeHeader { data_kind: "transactions" }.into()))?;
                        }

                        // Accumulate proto transactions (no deserialization)
                        current_transactions.extend(txs.executed_transactions.into_iter());
                    }

                    Some(checkpoint_data::Payload::Events(events)) => {
                        if current_sequence_number.is_none() {
                            Err(GrpcError::Protocol(CheckpointStreamError::DataBeforeHeader { data_kind: "events" }.into()))?;
                        }

                        // Accumulate proto events (no deserialization)
                        current_events.extend(events.events);
                    }

                    Some(checkpoint_data::Payload::EndMarker(marker)) => {
                        // End of current checkpoint - assemble the result and yield it
                         let sequence_number = current_sequence_number
                        .take()
                        .ok_or_else(|| -> GrpcError { GrpcError::Protocol(CheckpointStreamError::DataBeforeHeader { data_kind: "end marker" }.into()) })?;

                        let marker_sequence_number = marker.sequence_number
                        .ok_or_else(|| -> GrpcError { TryFromProtoError::missing("end_marker.sequence_number").into() })?;

                        if marker_sequence_number != sequence_number {
                            Err(GrpcError::Protocol(CheckpointStreamError::SequenceNumberMismatch {
                                expected: sequence_number,
                                actual: marker_sequence_number,
                            }.into()))?;
                        }

                        let response = CheckpointResponse {
                            sequence_number,
                            summary: current_summary.take(),
                            signature: current_signature.take(),
                            contents: current_contents.take(),
                            executed_transactions: std::mem::take(&mut current_transactions),
                            events: std::mem::take(&mut current_events),
                        };

                        yield CheckpointStreamItem::Checkpoint(Box::new(response));
                    }

                    Some(checkpoint_data::Payload::Progress(progress)) => {
                        yield CheckpointStreamItem::Progress {
                            latest_scanned_sequence_number: progress.latest_scanned_sequence_number,
                        };
                    }

                    None => {
                        // Empty payload - skip
                        continue;
                    }

                    Some(_) => {
                        // Unknown payload type
                        Err(GrpcError::Protocol(CheckpointStreamError::UnknownPayload.into()))?;
                    }
                }
            }

            // Check if stream ended with incomplete checkpoint data
            if let Some(sequence_number) = current_sequence_number {
                Err(GrpcError::Protocol(CheckpointStreamError::IncompleteStream { sequence_number }.into()))?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use iota_grpc_types::{
        read_mask_fields::{CheckpointResponseField, CheckpointResponseReadMask},
        v1::{
            filter as grpc_filter,
            ledger_service::{StreamCheckpointsRequest, get_checkpoint_request::CheckpointId},
        },
    };
    use iota_types::CheckpointDigest;

    use crate::GrpcClient;

    #[tokio::test]
    async fn each_entry_method_selects_its_checkpoint() {
        let client = GrpcClient::new("http://localhost").unwrap();
        assert_eq!(
            client.checkpoint_latest().checkpoint_id,
            CheckpointId::Latest(true)
        );
        assert_eq!(
            client.checkpoint_by_sequence_number(7).checkpoint_id,
            CheckpointId::SequenceNumber(7)
        );
        assert_eq!(
            client
                .checkpoint_by_digest(CheckpointDigest::ZERO)
                .checkpoint_id,
            CheckpointId::Digest(CheckpointDigest::ZERO.into())
        );
    }

    #[tokio::test]
    async fn setters_replace_the_unfiltered_default_request() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let query = client.checkpoint_latest();
        assert_eq!(query.transactions_filter, None);
        assert_eq!(query.events_filter, None);
        assert_eq!(
            query.read_mask.as_str(),
            CheckpointResponseReadMask::default().as_str()
        );

        let query = query
            .transactions_filter(grpc_filter::TransactionFilter::default())
            .events_filter(grpc_filter::EventFilter::default())
            .read_mask(CheckpointResponseField::CHECKPOINT_CONTENTS);
        assert_eq!(
            query.transactions_filter,
            Some(grpc_filter::TransactionFilter::default())
        );
        assert_eq!(
            query.events_filter,
            Some(grpc_filter::EventFilter::default())
        );
        assert_eq!(
            query.read_mask.as_str(),
            CheckpointResponseReadMask::from(CheckpointResponseField::CHECKPOINT_CONTENTS).as_str()
        );
    }

    #[tokio::test]
    async fn checkpoints_stream_defaults_to_an_open_unfiltered_range() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let options = client.checkpoints_stream().options;
        assert_eq!(options.start_sequence_number, None);
        assert_eq!(options.end_sequence_number, None);
        assert_eq!(options.transactions_filter, None);
        assert_eq!(options.events_filter, None);
        assert_eq!(
            options.read_mask.as_str(),
            CheckpointResponseReadMask::default().as_str()
        );
    }

    #[tokio::test]
    async fn stream_setters_fill_the_request_options() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let options = client
            .checkpoints_stream()
            .start_sequence_number(3)
            .end_sequence_number(9)
            .transactions_filter(grpc_filter::TransactionFilter::default())
            .events_filter(grpc_filter::EventFilter::default())
            .read_mask(CheckpointResponseField::CHECKPOINT_CONTENTS)
            .options;
        assert_eq!(options.start_sequence_number, Some(3));
        assert_eq!(options.end_sequence_number, Some(9));
        assert_eq!(
            options.transactions_filter,
            Some(grpc_filter::TransactionFilter::default())
        );
        assert_eq!(
            options.events_filter,
            Some(grpc_filter::EventFilter::default())
        );
        assert_eq!(
            options.read_mask.as_str(),
            CheckpointResponseReadMask::from(CheckpointResponseField::CHECKPOINT_CONTENTS).as_str()
        );
    }

    #[tokio::test]
    async fn filtered_stream_takes_the_same_setters_and_a_progress_interval() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let query = client.checkpoints_stream_filtered();
        assert_eq!(query.progress_interval_ms, None);

        let query = query.start_sequence_number(3).progress_interval_ms(1_000);
        assert_eq!(query.options.start_sequence_number, Some(3));
        assert_eq!(query.progress_interval_ms, Some(1_000));
    }

    #[tokio::test]
    async fn unfiltered_request_leaves_out_filtering_and_progress() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let (_, request) = client
            .checkpoints_stream()
            .start_sequence_number(3)
            .into_request();
        assert_eq!(request.start_sequence_number, Some(3));
        assert_eq!(request.filter_checkpoints, None);
        assert_eq!(request.progress_interval_ms, None);
    }

    #[tokio::test]
    async fn filtered_request_carries_filtering_and_progress() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let (_, request) = client
            .checkpoints_stream_filtered()
            .transactions_filter(grpc_filter::TransactionFilter::default())
            .progress_interval_ms(1_000)
            .into_request();
        assert_eq!(request.filter_checkpoints, Some(true));
        assert_eq!(request.progress_interval_ms, Some(1_000));
        assert_eq!(
            request.transactions_filter,
            Some(grpc_filter::TransactionFilter::default())
        );
    }

    #[tokio::test]
    async fn the_request_carries_the_checkpoint_the_filters_the_mask_and_the_message_size() {
        let client = GrpcClient::new("http://localhost")
            .unwrap()
            .with_max_decoding_message_size(1024);
        let (_, request) = client
            .checkpoint_by_sequence_number(7)
            .transactions_filter(grpc_filter::TransactionFilter::default())
            .events_filter(grpc_filter::EventFilter::default())
            .read_mask(CheckpointResponseField::CHECKPOINT_CONTENTS)
            .into_request()
            .unwrap();
        assert_eq!(request.checkpoint_id, Some(CheckpointId::SequenceNumber(7)));
        assert_eq!(
            request.transactions_filter,
            Some(grpc_filter::TransactionFilter::default())
        );
        assert_eq!(
            request.events_filter,
            Some(grpc_filter::EventFilter::default())
        );
        assert_eq!(
            request.read_mask,
            Some(
                CheckpointResponseReadMask::from(CheckpointResponseField::CHECKPOINT_CONTENTS)
                    .into()
            )
        );
        assert_eq!(request.max_message_size_bytes, Some(1024));
    }

    #[tokio::test]
    async fn the_request_leaves_unset_filters_unset() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let (_, request) = client.checkpoint_latest().into_request().unwrap();
        assert_eq!(request.checkpoint_id, Some(CheckpointId::Latest(true)));
        assert_eq!(request.transactions_filter, None);
        assert_eq!(request.events_filter, None);
        assert_eq!(request.max_message_size_bytes, None);
    }

    #[tokio::test]
    async fn unfiltered_request_carries_every_setter() {
        let client = GrpcClient::new("http://localhost")
            .unwrap()
            .with_max_decoding_message_size(1024);
        let (_, request) = client
            .checkpoints_stream()
            .start_sequence_number(3)
            .end_sequence_number(9)
            .transactions_filter(grpc_filter::TransactionFilter::default())
            .events_filter(grpc_filter::EventFilter::default())
            .read_mask(CheckpointResponseField::CHECKPOINT_CONTENTS)
            .into_request();
        assert_request_carries_every_setter(&request);
        assert_eq!(request.filter_checkpoints, None);
    }

    #[tokio::test]
    async fn filtered_request_carries_every_setter() {
        let client = GrpcClient::new("http://localhost")
            .unwrap()
            .with_max_decoding_message_size(1024);
        let (_, request) = client
            .checkpoints_stream_filtered()
            .start_sequence_number(3)
            .end_sequence_number(9)
            .transactions_filter(grpc_filter::TransactionFilter::default())
            .events_filter(grpc_filter::EventFilter::default())
            .read_mask(CheckpointResponseField::CHECKPOINT_CONTENTS)
            .into_request();
        assert_request_carries_every_setter(&request);
        assert_eq!(request.filter_checkpoints, Some(true));
    }

    fn assert_request_carries_every_setter(request: &StreamCheckpointsRequest) {
        assert_eq!(request.start_sequence_number, Some(3));
        assert_eq!(request.end_sequence_number, Some(9));
        assert_eq!(
            request.transactions_filter,
            Some(grpc_filter::TransactionFilter::default())
        );
        assert_eq!(
            request.events_filter,
            Some(grpc_filter::EventFilter::default())
        );
        assert_eq!(
            request.read_mask,
            Some(
                CheckpointResponseReadMask::from(CheckpointResponseField::CHECKPOINT_CONTENTS)
                    .into()
            )
        );
        assert_eq!(request.max_message_size_bytes, Some(1024));
    }
}
