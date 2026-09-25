// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for checkpoint queries.
//!
//! # Read Mask
//!
//! All checkpoint query methods accept a `read_mask` to control which data is
//! included in the response. Pass `CheckpointResponseReadMask::default()` for
//! the default mask, or a
//! [`CheckpointResponseField`](iota_grpc_types::read_mask_fields::CheckpointResponseField)
//! (or any slice/array/vec of fields) — conversion is automatic.

use std::pin::Pin;

use futures::{Stream, StreamExt};
use iota_grpc_types::{
    read_mask_fields::{CheckpointResponseReadMask, IntoReadMask},
    v1::{
        checkpoint, event, filter as grpc_filter,
        ledger_service::{
            GetCheckpointRequest, StreamCheckpointsRequest, checkpoint_data, get_checkpoint_request,
        },
        signatures::ValidatorAggregatedSignature as ProtoValidatorAggregatedSignature,
        transaction::ExecutedTransaction,
    },
};
use iota_types::{CheckpointDigest, CheckpointSequenceNumber};

use crate::{
    GrpcClient, GrpcError,
    api::{
        CheckpointResponse, CheckpointStreamError, CheckpointStreamItem, GrpcResult,
        MetadataEnvelope, ProtocolError, TryFromProtoError, saturating_usize_to_u32,
    },
};

impl GrpcClient {
    /// Get the latest checkpoint.
    ///
    /// Returns the checkpoint with fields populated according to the
    /// `read_mask`; use `CheckpointResponseReadMask::default()` for the
    /// default field mask. Pass a
    /// [`CheckpointResponseField`](iota_grpc_types::read_mask_fields::CheckpointResponseField)
    /// or any slice/array/vec of fields — conversion is automatic.
    ///
    /// # Parameters
    ///
    /// * `transactions_filter` - Optional filter to apply to transactions
    /// * `events_filter` - Optional filter to apply to events
    /// * `read_mask` - Field mask controlling the returned fields
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # use iota_sdk_grpc_client::read_mask_fields::CheckpointResponseReadMask;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    /// let checkpoint = client
    ///     .checkpoint_latest(None, None, CheckpointResponseReadMask::default())
    ///     .await?;
    /// println!(
    ///     "Received checkpoint {}",
    ///     checkpoint.body().sequence_number()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub async fn checkpoint_latest(
        &self,
        transactions_filter: impl Into<Option<grpc_filter::TransactionFilter>>,
        events_filter: impl Into<Option<grpc_filter::EventFilter>>,
        read_mask: impl IntoReadMask<CheckpointResponseReadMask>,
    ) -> GrpcResult<MetadataEnvelope<CheckpointResponse>> {
        self.checkpoint_internal(
            get_checkpoint_request::CheckpointId::Latest(true),
            transactions_filter.into(),
            events_filter.into(),
            read_mask.into_read_mask(),
        )
        .await
    }

    /// Get checkpoint by sequence number.
    ///
    /// Returns the checkpoint with fields populated according to the
    /// `read_mask`; use `CheckpointResponseReadMask::default()` for the
    /// default field mask. Pass a
    /// [`CheckpointResponseField`](iota_grpc_types::read_mask_fields::CheckpointResponseField)
    /// or any slice/array/vec of fields — conversion is automatic.
    ///
    /// # Parameters
    ///
    /// * `sequence_number` - The checkpoint sequence number to fetch
    /// * `transactions_filter` - Optional filter to apply to transactions
    /// * `events_filter` - Optional filter to apply to events
    /// * `read_mask` - Field mask controlling the returned fields
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # use iota_sdk_grpc_client::read_mask_fields::CheckpointResponseReadMask;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    /// let checkpoint = client
    ///     .checkpoint_by_sequence_number(100, None, None, CheckpointResponseReadMask::default())
    ///     .await?;
    /// println!(
    ///     "Received checkpoint {}",
    ///     checkpoint.body().sequence_number()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub async fn checkpoint_by_sequence_number(
        &self,
        sequence_number: CheckpointSequenceNumber,
        transactions_filter: impl Into<Option<grpc_filter::TransactionFilter>>,
        events_filter: impl Into<Option<grpc_filter::EventFilter>>,
        read_mask: impl IntoReadMask<CheckpointResponseReadMask>,
    ) -> GrpcResult<MetadataEnvelope<CheckpointResponse>> {
        self.checkpoint_internal(
            get_checkpoint_request::CheckpointId::SequenceNumber(sequence_number),
            transactions_filter.into(),
            events_filter.into(),
            read_mask.into_read_mask(),
        )
        .await
    }

    /// Get checkpoint by digest.
    ///
    /// Returns the checkpoint with fields populated according to the
    /// `read_mask`; use `CheckpointResponseReadMask::default()` for the
    /// default field mask. Pass a
    /// [`CheckpointResponseField`](iota_grpc_types::read_mask_fields::CheckpointResponseField)
    /// or any slice/array/vec of fields — conversion is automatic.
    ///
    /// # Parameters
    ///
    /// * `digest` - The checkpoint digest to fetch
    /// * `transactions_filter` - Optional filter to apply to transactions
    /// * `events_filter` - Optional filter to apply to events
    /// * `read_mask` - Field mask controlling the returned fields
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # use iota_sdk_grpc_client::read_mask_fields::CheckpointResponseReadMask;
    /// # use iota_types::CheckpointDigest;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    /// let digest: CheckpointDigest = todo!();
    /// let checkpoint = client
    ///     .checkpoint_by_digest(digest, None, None, CheckpointResponseReadMask::default())
    ///     .await?;
    /// println!(
    ///     "Received checkpoint {}",
    ///     checkpoint.body().sequence_number()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub async fn checkpoint_by_digest(
        &self,
        digest: CheckpointDigest,
        transactions_filter: impl Into<Option<grpc_filter::TransactionFilter>>,
        events_filter: impl Into<Option<grpc_filter::EventFilter>>,
        read_mask: impl IntoReadMask<CheckpointResponseReadMask>,
    ) -> GrpcResult<MetadataEnvelope<CheckpointResponse>> {
        self.checkpoint_internal(
            get_checkpoint_request::CheckpointId::Digest(digest.into()),
            transactions_filter.into(),
            events_filter.into(),
            read_mask.into_read_mask(),
        )
        .await
    }

    /// Internal helper to fetch checkpoint by any ID type.
    async fn checkpoint_internal(
        &self,
        checkpoint_id: get_checkpoint_request::CheckpointId,
        transactions_filter: Option<grpc_filter::TransactionFilter>,
        events_filter: Option<grpc_filter::EventFilter>,
        read_mask: CheckpointResponseReadMask,
    ) -> GrpcResult<MetadataEnvelope<CheckpointResponse>> {
        let mut request = match checkpoint_id {
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
        .with_read_mask(read_mask);

        if let Some(tf) = transactions_filter {
            request = request.with_transactions_filter(tf);
        }
        if let Some(ef) = events_filter {
            request = request.with_events_filter(ef);
        }
        if let Some(max_size) = self
            .max_decoding_message_size()
            .map(saturating_usize_to_u32)
        {
            request = request.with_max_message_size_bytes(max_size);
        }

        let mut client = self.ledger_service_client();
        let response = client.get_checkpoint(request).await?;
        let (stream, metadata) = MetadataEnvelope::from(response).into_parts();

        let reassembled = Self::reassemble_checkpoint_data_stream(stream);
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

    /// Start building a checkpoint stream.
    pub fn checkpoints_stream_builder(&self) -> CheckpointsStreamBuilder {
        CheckpointsStreamBuilder::new(self.clone())
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

/// Options for a checkpoint stream, created by
/// [`GrpcClient::checkpoints_stream_builder`].
///
/// With no option set, the stream starts at the latest checkpoint, never
/// ends, applies no filters and uses `CheckpointResponseReadMask::default()`.
#[derive(Clone)]
pub struct CheckpointsStreamBuilder {
    client: GrpcClient,
    start_sequence_number: Option<CheckpointSequenceNumber>,
    end_sequence_number: Option<CheckpointSequenceNumber>,
    transactions_filter: Option<grpc_filter::TransactionFilter>,
    events_filter: Option<grpc_filter::EventFilter>,
    progress_interval_ms: Option<u32>,
    read_mask: CheckpointResponseReadMask,
}

impl CheckpointsStreamBuilder {
    fn new(client: GrpcClient) -> Self {
        Self {
            client,
            start_sequence_number: None,
            end_sequence_number: None,
            transactions_filter: None,
            events_filter: None,
            progress_interval_ms: None,
            read_mask: CheckpointResponseReadMask::default(),
        }
    }

    /// Starting checkpoint. If unset, the stream starts from the latest
    /// checkpoint.
    pub fn start_sequence_number(
        mut self,
        start_sequence_number: impl Into<Option<CheckpointSequenceNumber>>,
    ) -> Self {
        self.start_sequence_number = start_sequence_number.into();
        self
    }

    /// Ending checkpoint. If unset, the stream continues indefinitely.
    pub fn end_sequence_number(
        mut self,
        end_sequence_number: impl Into<Option<CheckpointSequenceNumber>>,
    ) -> Self {
        self.end_sequence_number = end_sequence_number.into();
        self
    }

    /// Narrows the transactions returned for each checkpoint by
    /// [`stream`](Self::stream); decides which checkpoints are returned at
    /// all by [`stream_filtered`](Self::stream_filtered).
    pub fn transactions_filter(
        mut self,
        transactions_filter: impl Into<Option<grpc_filter::TransactionFilter>>,
    ) -> Self {
        self.transactions_filter = transactions_filter.into();
        self
    }

    /// Narrows the events returned for each checkpoint by
    /// [`stream`](Self::stream); decides which checkpoints are returned at
    /// all by [`stream_filtered`](Self::stream_filtered).
    pub fn events_filter(
        mut self,
        events_filter: impl Into<Option<grpc_filter::EventFilter>>,
    ) -> Self {
        self.events_filter = events_filter.into();
        self
    }

    /// Interval between progress messages in milliseconds, read only by
    /// [`stream_filtered`](Self::stream_filtered). Defaults to 2000ms.
    /// Minimum 500ms.
    pub fn progress_interval_ms(mut self, progress_interval_ms: impl Into<Option<u32>>) -> Self {
        self.progress_interval_ms = progress_interval_ms.into();
        self
    }

    /// Field mask controlling the returned fields. Pass a
    /// [`CheckpointResponseField`](iota_grpc_types::read_mask_fields::CheckpointResponseField)
    /// or any slice/array/vec of fields.
    pub fn read_mask(mut self, read_mask: impl IntoReadMask<CheckpointResponseReadMask>) -> Self {
        self.read_mask = read_mask.into_read_mask();
        self
    }

    /// Stream every checkpoint in the range, even those in which the filters
    /// match no transactions or events.
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
    ///     .checkpoints_stream_builder()
    ///     .start_sequence_number(0)
    ///     .end_sequence_number(10)
    ///     .stream()
    ///     .await?;
    ///
    /// while let Some(checkpoint) = stream.body_mut().next().await {
    ///     let checkpoint = checkpoint?;
    ///     println!("Received checkpoint {}", checkpoint.sequence_number());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn stream(
        self,
    ) -> GrpcResult<
        MetadataEnvelope<Pin<Box<dyn Stream<Item = GrpcResult<CheckpointResponse>> + Send>>>,
    > {
        let (stream, metadata) = self.open(false).await?.into_parts();
        let checkpoints = stream.filter_map(|item| async {
            match item {
                Ok(CheckpointStreamItem::Checkpoint(cp)) => Some(Ok(*cp)),
                Ok(CheckpointStreamItem::Progress { .. }) => None,
                Err(e) => Some(Err(e)),
            }
        });
        Ok(MetadataEnvelope::new(Box::pin(checkpoints), metadata))
    }

    /// Stream only the checkpoints in which the filters match a transaction
    /// or an event. At least one filter must be set.
    ///
    /// The stream yields [`CheckpointStreamItem::Checkpoint`] for each match
    /// and [`CheckpointStreamItem::Progress`] periodically while the server
    /// scans, to indicate liveness and the current scan position.
    ///
    /// For liveness detection, wrap `stream.next()` in
    /// `tokio::time::timeout()`: if neither a `Checkpoint` nor a `Progress`
    /// arrives within the progress interval plus some buffer for connection
    /// latency, the connection is likely dead.
    ///
    /// **Note:** The metadata in the returned [`MetadataEnvelope`] is captured
    /// from the initial gRPC response headers when the stream is opened. It is
    /// **not** updated as subsequent checkpoint data arrives.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::{GrpcClient, CheckpointStreamItem};
    /// # use iota_grpc_types::v1::filter as grpc_filter;
    /// # use futures::StreamExt;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    /// let mut stream = client
    ///     .checkpoints_stream_builder()
    ///     .start_sequence_number(0)
    ///     .transactions_filter(grpc_filter::TransactionFilter::default())
    ///     .stream_filtered()
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
    pub async fn stream_filtered(
        self,
    ) -> GrpcResult<
        MetadataEnvelope<Pin<Box<dyn Stream<Item = GrpcResult<CheckpointStreamItem>> + Send>>>,
    > {
        self.open(true).await
    }

    fn request(&self, filter_checkpoints: bool) -> StreamCheckpointsRequest {
        let mut request =
            StreamCheckpointsRequest::default().with_read_mask(self.read_mask.clone());

        if let Some(start) = self.start_sequence_number {
            request = request.with_start_sequence_number(start);
        }
        if let Some(end) = self.end_sequence_number {
            request = request.with_end_sequence_number(end);
        }
        if let Some(tf) = self.transactions_filter.clone() {
            request = request.with_transactions_filter(tf);
        }
        if let Some(ef) = self.events_filter.clone() {
            request = request.with_events_filter(ef);
        }
        if filter_checkpoints {
            request = request.with_filter_checkpoints(true);
            if let Some(ms) = self.progress_interval_ms {
                request = request.with_progress_interval_ms(ms);
            }
        }
        if let Some(max_size) = self
            .client
            .max_decoding_message_size()
            .map(saturating_usize_to_u32)
        {
            request = request.with_max_message_size_bytes(max_size);
        }
        request
    }

    async fn open(
        self,
        filter_checkpoints: bool,
    ) -> GrpcResult<
        MetadataEnvelope<Pin<Box<dyn Stream<Item = GrpcResult<CheckpointStreamItem>> + Send>>>,
    > {
        let request = self.request(filter_checkpoints);
        let mut client = self.client.ledger_service_client();
        let response = client.stream_checkpoints(request).await?;
        let (stream, metadata) = MetadataEnvelope::from(response).into_parts();

        Ok(MetadataEnvelope::new(
            Box::pin(GrpcClient::reassemble_checkpoint_data_stream(stream)),
            metadata,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn builder() -> CheckpointsStreamBuilder {
        GrpcClient::new_localnet()
            .unwrap()
            .checkpoints_stream_builder()
            .start_sequence_number(3)
            .end_sequence_number(7)
            .transactions_filter(grpc_filter::TransactionFilter::default())
            .progress_interval_ms(900)
    }

    #[tokio::test]
    async fn stream_request_leaves_out_filtering_and_progress() {
        let request = builder().request(false);
        assert_eq!(request.start_sequence_number, Some(3));
        assert_eq!(request.end_sequence_number, Some(7));
        assert!(request.transactions_filter.is_some());
        assert!(request.events_filter.is_none());
        assert_ne!(request.filter_checkpoints, Some(true));
        assert_eq!(request.progress_interval_ms, None);
    }

    #[tokio::test]
    async fn stream_filtered_request_carries_filtering_and_progress() {
        let request = builder().request(true);
        assert_eq!(request.filter_checkpoints, Some(true));
        assert_eq!(request.progress_interval_ms, Some(900));
    }
}
