// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Checkpoints API implementation.

use std::sync::Arc;

use futures::stream::BoxStream;
use iota_sdk::grpc_client::{
    GrpcResult,
    read_mask_fields::{
        CheckpointResponseField as SdkCheckpointResponseField, CheckpointResponseReadMask,
    },
};

use crate::{
    error::{Result, SdkFfiError},
    grpc::{
        api::{ledger::transactions::ExecutedTransaction, read_mask_requests},
        client::GrpcClient,
        filters::{GrpcEventFilter, GrpcTransactionFilter},
        read_mask_fields::CheckpointResponseField,
    },
    stream::StreamHandle,
    types::{
        checkpoint::{CheckpointContents, CheckpointSummary},
        digest::{CheckpointContentsDigest, CheckpointDigest},
        events::Event,
        validator::ValidatorAggregatedSignature,
    },
};

/// Response for a checkpoint query.
///
/// Which fields are populated depends on the read mask used for the query;
/// the default read mask only includes the checkpoint summary, and every
/// other field is `None`.
///
/// The `summary`, `signature`, `contents`, and `events` fields are
/// deserialized from BCS, so the read mask must include the corresponding
/// `bcs` sub-fields for them to be populated; digest-only read masks populate
/// only the digest fields.
#[derive(uniffi::Record)]
pub struct CheckpointResponse {
    /// The checkpoint sequence number. Always available regardless of the
    /// read mask.
    pub sequence_number: u64,
    /// The digest of the checkpoint summary.
    pub summary_digest: Option<Arc<CheckpointDigest>>,
    /// The checkpoint summary.
    pub summary: Option<Arc<CheckpointSummary>>,
    /// The aggregated validator signature of the checkpoint.
    pub signature: Option<Arc<ValidatorAggregatedSignature>>,
    /// The digest of the checkpoint contents.
    pub contents_digest: Option<Arc<CheckpointContentsDigest>>,
    /// The checkpoint contents.
    pub contents: Option<Arc<CheckpointContents>>,
    /// The transactions executed in the checkpoint. `None` unless the read
    /// mask requests `transactions` or one of its sub-fields; with a
    /// transactions filter that matches nothing, an empty list.
    pub transactions: Option<Vec<ExecutedTransaction>>,
    /// The events emitted in the checkpoint. `None` unless the read mask
    /// requests `events.bcs`; a checkpoint with no events, or an events
    /// filter that matches nothing, yields an empty list.
    pub events: Option<Vec<Event>>,
}

impl CheckpointResponse {
    /// Convert a client response, using the read mask it was requested with
    /// to tell fields that were not requested from fields that are empty.
    fn from_response(
        value: &iota_sdk::grpc_client::CheckpointResponse,
        read_mask: &CheckpointResponseReadMask,
    ) -> Result<Self> {
        let summary = value.summary().ok();
        let contents = value.contents().ok();
        Ok(Self {
            sequence_number: value.sequence_number(),
            summary_digest: summary
                .and_then(|summary| summary.digest.as_ref())
                .map(iota_sdk::types::CheckpointDigest::try_from)
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
                .filter(|signature| signature.bcs.is_some())
                .map(|signature| signature.signature().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            contents_digest: contents
                .and_then(|contents| contents.digest.as_ref())
                .map(iota_sdk::types::CheckpointContentsDigest::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            contents: contents
                .filter(|contents| contents.bcs.is_some())
                .map(|contents| contents.contents().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            transactions: read_mask_requests(read_mask, SdkCheckpointResponseField::TRANSACTIONS)
                .then(|| {
                    value
                        .executed_transactions()
                        .iter()
                        .map(TryInto::try_into)
                        .collect::<Result<Vec<_>>>()
                })
                .transpose()?,
            events: read_mask_requests(read_mask, SdkCheckpointResponseField::EVENTS_BCS)
                .then(|| {
                    value
                        .events()
                        .iter()
                        .map(|event| event.event().map(Into::into).map_err(SdkFfiError::new))
                        .collect::<Result<Vec<_>>>()
                })
                .transpose()?,
        })
    }
}

/// Define a handle object over a server-streaming checkpoint RPC.
///
/// The Rust API exposes these as a `Stream`, which has no uniffi equivalent,
/// so the handle is pulled one item at a time with `next` and closed with
/// `cancel`. The handle keeps the read mask the stream was opened with, since
/// converting an item needs it.
macro_rules! define_checkpoint_stream {
    ($(#[$meta:meta])* $name:ident, $item:ty, $ffi_item:ty, $convert:expr) => {
        $(#[$meta])*
        ///
        /// Call `next` in a loop to receive items; it returns `None` once the
        /// stream is exhausted or `cancel` has been called.
        #[derive(uniffi::Object)]
        pub struct $name {
            stream: StreamHandle<BoxStream<'static, GrpcResult<$item>>>,
            read_mask: CheckpointResponseReadMask,
        }

        #[uniffi::export(async_runtime = "tokio")]
        impl $name {
            /// Get the next item from the stream.
            ///
            /// Returns `None` once the stream is exhausted or has been
            /// canceled. Concurrent calls are serialized; there is no ordering
            /// guarantee between them.
            ///
            /// An error from the connection or the server ends the stream:
            /// there is no reconnect, so every later call returns `None`, and
            /// a caller that wants to resume must open a new stream from the
            /// last sequence number it received. An error converting a single
            /// item, such as a BCS decode failure, only affects that item; the
            /// next call continues with the following one.
            pub async fn next(&self) -> Result<Option<$ffi_item>> {
                self.stream
                    .next()
                    .await
                    .transpose()?
                    .map(|item| ($convert)(item, &self.read_mask))
                    .transpose()
            }

            /// Cancel the stream, dropping the connection and unblocking a
            /// pending `next`.
            ///
            /// Idempotent, and safe to call while `next` is pending — the
            /// pending call drops the connection on its way out.
            ///
            /// Named `cancel` rather than `close` because a `close` method
            /// collides with the disposal method uniffi generates for objects
            /// in some languages.
            pub fn cancel(&self) {
                self.stream.cancel();
            }

            /// Whether the stream has been canceled.
            pub fn is_canceled(&self) -> bool {
                self.stream.is_canceled()
            }
        }

        impl $name {
            fn new(
                stream: BoxStream<'static, GrpcResult<$item>>,
                read_mask: CheckpointResponseReadMask,
            ) -> Self {
                Self {
                    stream: StreamHandle::new(stream),
                    read_mask,
                }
            }
        }
    };
}

define_checkpoint_stream!(
    /// A stream of checkpoints returned by [`GrpcClient::checkpoints_stream`].
    CheckpointStream,
    iota_sdk::grpc_client::CheckpointResponse,
    CheckpointResponse,
    |checkpoint, read_mask| CheckpointResponse::from_response(&checkpoint, read_mask)
);

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

impl CheckpointStreamItem {
    fn from_item(
        value: iota_sdk::grpc_client::CheckpointStreamItem,
        read_mask: &CheckpointResponseReadMask,
    ) -> Result<Self> {
        Ok(match value {
            iota_sdk::grpc_client::CheckpointStreamItem::Checkpoint(checkpoint) => {
                Self::Checkpoint {
                    checkpoint: CheckpointResponse::from_response(&checkpoint, read_mask)?,
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

define_checkpoint_stream!(
    /// A stream of filtered checkpoints returned by
    /// [`GrpcClient::checkpoints_stream_filtered`].
    FilteredCheckpointStream,
    iota_sdk::grpc_client::CheckpointStreamItem,
    CheckpointStreamItem,
    CheckpointStreamItem::from_item
);

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
        read_mask: Option<Vec<CheckpointResponseField>>,
    ) -> Result<CheckpointResponse> {
        let read_mask = crate::grpc::api::read_mask::<CheckpointResponseReadMask, _>(read_mask);
        let response = self
            .client()
            .checkpoint_latest(
                transactions_filter.as_deref().map(Into::into),
                events_filter.as_deref().map(Into::into),
                read_mask.clone(),
            )
            .await?
            .into_inner();
        CheckpointResponse::from_response(&response, &read_mask)
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
        read_mask: Option<Vec<CheckpointResponseField>>,
    ) -> Result<CheckpointResponse> {
        let read_mask = crate::grpc::api::read_mask::<CheckpointResponseReadMask, _>(read_mask);
        let response = self
            .client()
            .checkpoint_by_sequence_number(
                sequence_number,
                transactions_filter.as_deref().map(Into::into),
                events_filter.as_deref().map(Into::into),
                read_mask.clone(),
            )
            .await?
            .into_inner();
        CheckpointResponse::from_response(&response, &read_mask)
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
        read_mask: Option<Vec<CheckpointResponseField>>,
    ) -> Result<CheckpointResponse> {
        let read_mask = crate::grpc::api::read_mask::<CheckpointResponseReadMask, _>(read_mask);
        let response = self
            .client()
            .checkpoint_by_digest(
                **digest,
                transactions_filter.as_deref().map(Into::into),
                events_filter.as_deref().map(Into::into),
                read_mask.clone(),
            )
            .await?
            .into_inner();
        CheckpointResponse::from_response(&response, &read_mask)
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
        read_mask: Option<Vec<CheckpointResponseField>>,
    ) -> Result<CheckpointStream> {
        let read_mask = crate::grpc::api::read_mask::<CheckpointResponseReadMask, _>(read_mask);
        let stream = self
            .client()
            .checkpoints_stream(
                start_sequence_number,
                end_sequence_number,
                transactions_filter.as_deref().map(Into::into),
                events_filter.as_deref().map(Into::into),
                read_mask.clone(),
            )
            .await?
            .into_inner();
        Ok(CheckpointStream::new(stream, read_mask))
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
        read_mask: Option<Vec<CheckpointResponseField>>,
    ) -> Result<FilteredCheckpointStream> {
        let read_mask = crate::grpc::api::read_mask::<CheckpointResponseReadMask, _>(read_mask);
        let stream = self
            .client()
            .checkpoints_stream_filtered(
                start_sequence_number,
                end_sequence_number,
                transactions_filter.as_deref().map(Into::into),
                events_filter.as_deref().map(Into::into),
                progress_interval_ms,
                read_mask.clone(),
            )
            .await?
            .into_inner();
        Ok(FilteredCheckpointStream::new(stream, read_mask))
    }
}
