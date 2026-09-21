// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Checkpoints API implementation.

use std::{pin::Pin, sync::Arc};

use futures::{Stream, StreamExt};
use iota_sdk::grpc_client::read_mask_fields::CheckpointResponseReadMask;
use tokio::sync::Mutex;

use crate::{
    error::{Result, SdkFfiError},
    grpc::{
        api::ledger::transactions::ExecutedTransaction,
        client::GrpcClient,
        filters::{GrpcEventFilter, GrpcTransactionFilter},
    },
    types::{
        checkpoint::{CheckpointContents, CheckpointSummary},
        digest::{CheckpointDigest, Digest},
        events::Event,
        validator::ValidatorAggregatedSignature,
    },
};

/// Extract the inner proto transaction filter from an optional FFI filter.
fn to_proto_transactions_filter(
    filter: &Option<Arc<GrpcTransactionFilter>>,
) -> Option<iota_sdk::grpc_types::v1::filter::TransactionFilter> {
    filter.as_ref().map(|filter| filter.0.clone())
}

/// Extract the inner proto event filter from an optional FFI filter.
fn to_proto_events_filter(
    filter: &Option<Arc<GrpcEventFilter>>,
) -> Option<iota_sdk::grpc_types::v1::filter::EventFilter> {
    filter.as_ref().map(|filter| filter.0.clone())
}

/// Response for a checkpoint query.
///
/// Which fields are populated depends on the read mask used for the query;
/// the default read mask only includes the checkpoint summary.
///
/// The `summary`, `contents`, and `events` fields are deserialized from BCS,
/// so the read mask must include the corresponding `bcs` sub-fields for them
/// to be populated; digest-only read masks populate only the digest fields.
#[derive(uniffi::Record)]
pub struct CheckpointResponse {
    /// The checkpoint sequence number. Always available regardless of the
    /// read mask.
    pub sequence_number: u64,
    /// The digest of the checkpoint summary.
    pub summary_digest: Option<Arc<Digest>>,
    /// The checkpoint summary.
    pub summary: Option<Arc<CheckpointSummary>>,
    /// The aggregated validator signature of the checkpoint.
    pub signature: Option<Arc<ValidatorAggregatedSignature>>,
    /// The digest of the checkpoint contents.
    pub contents_digest: Option<Arc<Digest>>,
    /// The checkpoint contents.
    pub contents: Option<Arc<CheckpointContents>>,
    /// The transactions executed in the checkpoint.
    pub transactions: Vec<ExecutedTransaction>,
    /// The events emitted in the checkpoint. Only events whose BCS
    /// representation was requested are included.
    pub events: Vec<Event>,
}

impl TryFrom<&iota_sdk::grpc_client::CheckpointResponse> for CheckpointResponse {
    type Error = SdkFfiError;

    fn try_from(value: &iota_sdk::grpc_client::CheckpointResponse) -> Result<Self> {
        let summary = value.summary().ok();
        let contents = value.contents().ok();
        Ok(Self {
            sequence_number: value.sequence_number(),
            summary_digest: summary
                .and_then(|summary| summary.digest.as_ref())
                .map(iota_sdk::types::Digest::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            summary: summary
                .filter(|summary| summary.bcs.is_some())
                .map(|summary| summary.summary().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            signature: value
                .signature()
                .ok()
                .map(|signature| signature.signature().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            contents_digest: contents
                .and_then(|contents| contents.digest.as_ref())
                .map(iota_sdk::types::Digest::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            contents: contents
                .filter(|contents| contents.bcs.is_some())
                .map(|contents| contents.contents().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            transactions: value
                .executed_transactions()
                .iter()
                .map(TryInto::try_into)
                .collect::<Result<_>>()?,
            events: value
                .events()
                .iter()
                .filter(|event| event.bcs.is_some())
                .map(|event| event.event().map_err(SdkFfiError::new))
                .collect::<std::result::Result<Vec<_>, _>>()?
                .into_iter()
                .map(Into::into)
                .collect(),
        })
    }
}

/// A stream of checkpoints returned by [`GrpcClient::checkpoints_stream`].
#[derive(uniffi::Object)]
pub struct CheckpointStream(
    Mutex<
        Pin<
            Box<
                dyn Stream<
                        Item = iota_sdk::grpc_client::GrpcResult<
                            iota_sdk::grpc_client::CheckpointResponse,
                        >,
                    > + Send,
            >,
        >,
    >,
);

#[uniffi::export(async_runtime = "tokio")]
impl CheckpointStream {
    /// Get the next checkpoint from the stream.
    ///
    /// Returns `None` once the stream is exhausted.
    pub async fn next(&self) -> Result<Option<CheckpointResponse>> {
        self.0
            .lock()
            .await
            .next()
            .await
            .transpose()?
            .as_ref()
            .map(TryInto::try_into)
            .transpose()
    }
}

/// An item yielded by a filtered checkpoint stream: either a checkpoint with
/// matching data, or a progress indicator emitted while the server scans
/// checkpoints that have none.
#[derive(uniffi::Enum)]
pub enum CheckpointStreamItem {
    /// A complete checkpoint with its transactions and events.
    Checkpoint { checkpoint: CheckpointResponse },
    /// A progress indicator sent during filtered scanning, carrying the
    /// sequence number of the latest scanned checkpoint.
    Progress { latest_scanned_sequence_number: u64 },
}

impl TryFrom<iota_sdk::grpc_client::CheckpointStreamItem> for CheckpointStreamItem {
    type Error = SdkFfiError;

    fn try_from(value: iota_sdk::grpc_client::CheckpointStreamItem) -> Result<Self> {
        Ok(match value {
            iota_sdk::grpc_client::CheckpointStreamItem::Checkpoint(checkpoint) => {
                Self::Checkpoint {
                    checkpoint: (&*checkpoint).try_into()?,
                }
            }
            iota_sdk::grpc_client::CheckpointStreamItem::Progress {
                latest_scanned_sequence_number,
            } => Self::Progress {
                latest_scanned_sequence_number,
            },
            _ => {
                return Err(SdkFfiError::custom(
                    "unsupported checkpoint stream item variant",
                ));
            }
        })
    }
}

/// A stream of filtered checkpoints returned by
/// [`GrpcClient::checkpoints_stream_filtered`].
#[derive(uniffi::Object)]
pub struct FilteredCheckpointStream(
    Mutex<
        Pin<
            Box<
                dyn Stream<
                        Item = iota_sdk::grpc_client::GrpcResult<
                            iota_sdk::grpc_client::CheckpointStreamItem,
                        >,
                    > + Send,
            >,
        >,
    >,
);

#[uniffi::export(async_runtime = "tokio")]
impl FilteredCheckpointStream {
    /// Get the next item from the stream.
    ///
    /// Returns `None` once the stream is exhausted.
    pub async fn next(&self) -> Result<Option<CheckpointStreamItem>> {
        self.0
            .lock()
            .await
            .next()
            .await
            .transpose()?
            .map(TryInto::try_into)
            .transpose()
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// Get the latest checkpoint.
    ///
    /// The optional `transactions_filter` and `events_filter` narrow the
    /// transactions and events returned for the checkpoint.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    /// If `None`, only the checkpoint summary is returned.
    #[uniffi::method(default(transactions_filter = None, events_filter = None, read_mask = None))]
    pub async fn checkpoint_latest(
        &self,
        transactions_filter: Option<Arc<GrpcTransactionFilter>>,
        events_filter: Option<Arc<GrpcEventFilter>>,
        read_mask: Option<Vec<String>>,
    ) -> Result<CheckpointResponse> {
        (&self
            .client()
            .checkpoint_latest(
                to_proto_transactions_filter(&transactions_filter),
                to_proto_events_filter(&events_filter),
                crate::grpc::api::read_mask::<CheckpointResponseReadMask>(&read_mask),
            )
            .await?
            .into_inner())
            .try_into()
    }

    /// Get a checkpoint by its sequence number.
    ///
    /// The optional `transactions_filter` and `events_filter` narrow the
    /// transactions and events returned for the checkpoint.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    /// If `None`, only the checkpoint summary is returned.
    #[uniffi::method(default(transactions_filter = None, events_filter = None, read_mask = None))]
    pub async fn checkpoint_by_sequence_number(
        &self,
        sequence_number: u64,
        transactions_filter: Option<Arc<GrpcTransactionFilter>>,
        events_filter: Option<Arc<GrpcEventFilter>>,
        read_mask: Option<Vec<String>>,
    ) -> Result<CheckpointResponse> {
        (&self
            .client()
            .checkpoint_by_sequence_number(
                sequence_number,
                to_proto_transactions_filter(&transactions_filter),
                to_proto_events_filter(&events_filter),
                crate::grpc::api::read_mask::<CheckpointResponseReadMask>(&read_mask),
            )
            .await?
            .into_inner())
            .try_into()
    }

    /// Get a checkpoint by its digest.
    ///
    /// The optional `transactions_filter` and `events_filter` narrow the
    /// transactions and events returned for the checkpoint.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    /// If `None`, only the checkpoint summary is returned.
    #[uniffi::method(default(transactions_filter = None, events_filter = None, read_mask = None))]
    pub async fn checkpoint_by_digest(
        &self,
        digest: &CheckpointDigest,
        transactions_filter: Option<Arc<GrpcTransactionFilter>>,
        events_filter: Option<Arc<GrpcEventFilter>>,
        read_mask: Option<Vec<String>>,
    ) -> Result<CheckpointResponse> {
        (&self
            .client()
            .checkpoint_by_digest(
                **digest,
                to_proto_transactions_filter(&transactions_filter),
                to_proto_events_filter(&events_filter),
                crate::grpc::api::read_mask::<CheckpointResponseReadMask>(&read_mask),
            )
            .await?
            .into_inner())
            .try_into()
    }

    /// Stream checkpoints across a range of sequence numbers.
    ///
    /// Every checkpoint in the range is yielded, even if the filters produce
    /// no matching transactions or events within it.
    ///
    /// If `start_sequence_number` is `None`, the stream starts from the latest
    /// checkpoint. If `end_sequence_number` is `None`, the stream continues
    /// indefinitely.
    ///
    /// The optional `transactions_filter` and `events_filter` narrow the
    /// transactions and events returned for each checkpoint.
    ///
    /// The optional `read_mask` controls which fields the server returns for
    /// each checkpoint. If `None`, only the checkpoint summary is returned.
    #[uniffi::method(default(
        start_sequence_number = None,
        end_sequence_number = None,
        transactions_filter = None,
        events_filter = None,
        read_mask = None
    ))]
    pub async fn checkpoints_stream(
        &self,
        start_sequence_number: Option<u64>,
        end_sequence_number: Option<u64>,
        transactions_filter: Option<Arc<GrpcTransactionFilter>>,
        events_filter: Option<Arc<GrpcEventFilter>>,
        read_mask: Option<Vec<String>>,
    ) -> Result<CheckpointStream> {
        let stream = self
            .client()
            .checkpoints_stream(
                start_sequence_number,
                end_sequence_number,
                to_proto_transactions_filter(&transactions_filter),
                to_proto_events_filter(&events_filter),
                crate::grpc::api::read_mask::<CheckpointResponseReadMask>(&read_mask),
            )
            .await?
            .into_inner();
        Ok(CheckpointStream(Mutex::new(stream)))
    }

    /// Stream checkpoints across a range of sequence numbers, skipping
    /// checkpoints with no data matching the filters.
    ///
    /// Unlike [`GrpcClient::checkpoints_stream`], the filters decide which
    /// checkpoints are returned at all; checkpoints without any matching
    /// transactions or events are skipped entirely. At least one of
    /// `transactions_filter` or `events_filter` must be set.
    ///
    /// While the server scans non-matching checkpoints, the stream yields
    /// progress items indicating the current scan position (default every
    /// 2000ms, configurable via `progress_interval_ms`, minimum 500ms).
    ///
    /// If `start_sequence_number` is `None`, the stream starts from the latest
    /// checkpoint. If `end_sequence_number` is `None`, the stream continues
    /// indefinitely.
    ///
    /// The optional `read_mask` controls which fields the server returns for
    /// each checkpoint. If `None`, only the checkpoint summary is returned.
    #[uniffi::method(default(
        start_sequence_number = None,
        end_sequence_number = None,
        transactions_filter = None,
        events_filter = None,
        progress_interval_ms = None,
        read_mask = None
    ))]
    pub async fn checkpoints_stream_filtered(
        &self,
        start_sequence_number: Option<u64>,
        end_sequence_number: Option<u64>,
        transactions_filter: Option<Arc<GrpcTransactionFilter>>,
        events_filter: Option<Arc<GrpcEventFilter>>,
        progress_interval_ms: Option<u32>,
        read_mask: Option<Vec<String>>,
    ) -> Result<FilteredCheckpointStream> {
        let stream = self
            .client()
            .checkpoints_stream_filtered(
                start_sequence_number,
                end_sequence_number,
                to_proto_transactions_filter(&transactions_filter),
                to_proto_events_filter(&events_filter),
                progress_interval_ms,
                crate::grpc::api::read_mask::<CheckpointResponseReadMask>(&read_mask),
            )
            .await?
            .into_inner();
        Ok(FilteredCheckpointStream(Mutex::new(stream)))
    }
}
