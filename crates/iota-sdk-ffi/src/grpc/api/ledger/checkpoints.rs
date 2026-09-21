// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Checkpoints API implementation.

use std::sync::Arc;

use futures::{StreamExt, stream::BoxStream};
use iota_sdk::grpc_client::{GrpcResult, read_mask_fields::CheckpointResponseReadMask};
use tokio::sync::Mutex;

use crate::{
    cancel::Cancel,
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

/// Response for a checkpoint query.
///
/// Which fields are populated depends on the read mask used for the query;
/// the default read mask only includes the checkpoint summary.
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
    /// The events emitted in the checkpoint. `None` unless the BCS
    /// representation of every event was requested; a checkpoint with no
    /// events yields an empty list.
    pub events: Option<Vec<Event>>,
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
                .filter(|signature| signature.bcs.is_some())
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
                .all(|event| event.bcs.is_some())
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
/// `cancel`.
macro_rules! define_checkpoint_stream {
    ($(#[$meta:meta])* $name:ident, $item:ty, $ffi_item:ty, $convert:expr) => {
        $(#[$meta])*
        ///
        /// Call `next` in a loop to receive items; it returns `None` once the
        /// stream is exhausted or `cancel` has been called.
        #[derive(uniffi::Object)]
        pub struct $name {
            stream: Mutex<BoxStream<'static, GrpcResult<$item>>>,
            cancel: Cancel,
        }

        #[uniffi::export(async_runtime = "tokio")]
        impl $name {
            /// Get the next item from the stream.
            ///
            /// Returns `None` once the stream is exhausted or has been
            /// canceled. Concurrent calls are serialized; there is no ordering
            /// guarantee between them.
            pub async fn next(&self) -> Result<Option<$ffi_item>> {
                if self.cancel.is_canceled() {
                    return Ok(None);
                }
                let mut stream = self.stream.lock().await;
                let canceled = std::pin::pin!(self.cancel.wait());
                let item = match futures::future::select(canceled, stream.next()).await {
                    futures::future::Either::Left(((), _)) => {
                        *stream = Self::drained();
                        None
                    }
                    futures::future::Either::Right((item, _)) => item,
                };
                item.transpose()?.map($convert).transpose()
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
                self.cancel.cancel();
                if let Ok(mut stream) = self.stream.try_lock() {
                    *stream = Self::drained();
                }
            }

            /// Whether the stream has been canceled.
            pub fn is_canceled(&self) -> bool {
                self.cancel.is_canceled()
            }
        }

        impl $name {
            fn new(stream: BoxStream<'static, GrpcResult<$item>>) -> Self {
                Self {
                    stream: Mutex::new(stream),
                    cancel: Cancel::default(),
                }
            }

            /// The stream a canceled handle is left with, so that canceling
            /// drops the RPC instead of holding it until the handle is freed.
            fn drained() -> BoxStream<'static, GrpcResult<$item>> {
                futures::stream::empty().boxed()
            }
        }
    };
}

define_checkpoint_stream!(
    /// A stream of checkpoints returned by [`GrpcClient::checkpoints_stream`].
    CheckpointStream,
    iota_sdk::grpc_client::CheckpointResponse,
    CheckpointResponse,
    |checkpoint| CheckpointResponse::try_from(&checkpoint)
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

define_checkpoint_stream!(
    /// A stream of filtered checkpoints returned by
    /// [`GrpcClient::checkpoints_stream_filtered`].
    FilteredCheckpointStream,
    iota_sdk::grpc_client::CheckpointStreamItem,
    CheckpointStreamItem,
    CheckpointStreamItem::try_from
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
        read_mask: Option<Vec<String>>,
    ) -> Result<CheckpointResponse> {
        (&self
            .client()
            .checkpoint_latest(
                transactions_filter.as_deref().map(Into::into),
                events_filter.as_deref().map(Into::into),
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
                transactions_filter.as_deref().map(Into::into),
                events_filter.as_deref().map(Into::into),
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
                transactions_filter.as_deref().map(Into::into),
                events_filter.as_deref().map(Into::into),
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
                transactions_filter.as_deref().map(Into::into),
                events_filter.as_deref().map(Into::into),
                crate::grpc::api::read_mask::<CheckpointResponseReadMask>(&read_mask),
            )
            .await?
            .into_inner();
        Ok(CheckpointStream::new(stream))
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
                transactions_filter.as_deref().map(Into::into),
                events_filter.as_deref().map(Into::into),
                progress_interval_ms,
                crate::grpc::api::read_mask::<CheckpointResponseReadMask>(&read_mask),
            )
            .await?
            .into_inner();
        Ok(FilteredCheckpointStream::new(stream))
    }
}
