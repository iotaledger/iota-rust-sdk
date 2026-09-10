// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Checkpoints API implementation.

use std::{pin::Pin, sync::Arc};

use futures::{Stream, StreamExt};
use iota_sdk::grpc_client::read_mask_fields::CheckpointResponseReadMask;
use tokio::sync::Mutex;

use crate::{
    error::Result,
    grpc::{
        client::GrpcClient,
        filters::{GrpcEventFilter, GrpcTransactionFilter},
        output_types::CheckpointResponse,
    },
    types::digest::CheckpointDigest,
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

/// A stream of checkpoints returned by [`GrpcClient::stream_checkpoints`].
#[derive(uniffi::Object)]
pub struct CheckpointStream(
    Mutex<
        Pin<
            Box<
                dyn Stream<
                        Item = iota_sdk::grpc_client::Result<
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
    type Error = crate::error::SdkFfiError;

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
            _ => unimplemented!("a new enum variant was added and needs to be handled"),
        })
    }
}

/// A stream of filtered checkpoints returned by
/// [`GrpcClient::stream_checkpoints_filtered`].
#[derive(uniffi::Object)]
pub struct FilteredCheckpointStream(
    Mutex<
        Pin<
            Box<
                dyn Stream<
                        Item = iota_sdk::grpc_client::Result<
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
    /// The optional `read_mask` controls which fields the server returns.
    /// If `None`, only the checkpoint summary is returned.
    ///
    /// The optional `transactions_filter` and `events_filter` narrow the
    /// transactions and events returned for the checkpoint.
    #[uniffi::method(default(read_mask = None, transactions_filter = None, events_filter = None))]
    pub async fn get_checkpoint_latest(
        &self,
        read_mask: Option<Vec<String>>,
        transactions_filter: Option<Arc<GrpcTransactionFilter>>,
        events_filter: Option<Arc<GrpcEventFilter>>,
    ) -> Result<CheckpointResponse> {
        (&self
            .0
            .read()
            .await
            .get_checkpoint_latest(
                to_proto_transactions_filter(&transactions_filter),
                to_proto_events_filter(&events_filter),
                super::read_mask::<CheckpointResponseReadMask>(&read_mask),
            )
            .await?
            .into_inner())
            .try_into()
    }

    /// Get a checkpoint by its sequence number.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    /// If `None`, only the checkpoint summary is returned.
    ///
    /// The optional `transactions_filter` and `events_filter` narrow the
    /// transactions and events returned for the checkpoint.
    #[uniffi::method(default(read_mask = None, transactions_filter = None, events_filter = None))]
    pub async fn get_checkpoint_by_sequence_number(
        &self,
        sequence_number: u64,
        read_mask: Option<Vec<String>>,
        transactions_filter: Option<Arc<GrpcTransactionFilter>>,
        events_filter: Option<Arc<GrpcEventFilter>>,
    ) -> Result<CheckpointResponse> {
        (&self
            .0
            .read()
            .await
            .get_checkpoint_by_sequence_number(
                sequence_number,
                to_proto_transactions_filter(&transactions_filter),
                to_proto_events_filter(&events_filter),
                super::read_mask::<CheckpointResponseReadMask>(&read_mask),
            )
            .await?
            .into_inner())
            .try_into()
    }

    /// Get a checkpoint by its digest.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    /// If `None`, only the checkpoint summary is returned.
    ///
    /// The optional `transactions_filter` and `events_filter` narrow the
    /// transactions and events returned for the checkpoint.
    #[uniffi::method(default(read_mask = None, transactions_filter = None, events_filter = None))]
    pub async fn get_checkpoint_by_digest(
        &self,
        digest: &CheckpointDigest,
        read_mask: Option<Vec<String>>,
        transactions_filter: Option<Arc<GrpcTransactionFilter>>,
        events_filter: Option<Arc<GrpcEventFilter>>,
    ) -> Result<CheckpointResponse> {
        (&self
            .0
            .read()
            .await
            .get_checkpoint_by_digest(
                **digest,
                to_proto_transactions_filter(&transactions_filter),
                to_proto_events_filter(&events_filter),
                super::read_mask::<CheckpointResponseReadMask>(&read_mask),
            )
            .await?
            .into_inner())
            .try_into()
    }

    /// Stream checkpoints across a range of sequence numbers.
    ///
    /// If `start_sequence_number` is `None`, the stream starts from the latest
    /// checkpoint. If `end_sequence_number` is `None`, the stream continues
    /// indefinitely.
    ///
    /// The optional `read_mask` controls which fields the server returns for
    /// each checkpoint. If `None`, only the checkpoint summary is returned.
    ///
    /// The optional `transactions_filter` and `events_filter` narrow the
    /// transactions and events returned for each checkpoint.
    #[uniffi::method(default(
        start_sequence_number = None,
        end_sequence_number = None,
        read_mask = None,
        transactions_filter = None,
        events_filter = None
    ))]
    pub async fn stream_checkpoints(
        &self,
        start_sequence_number: Option<u64>,
        end_sequence_number: Option<u64>,
        read_mask: Option<Vec<String>>,
        transactions_filter: Option<Arc<GrpcTransactionFilter>>,
        events_filter: Option<Arc<GrpcEventFilter>>,
    ) -> Result<CheckpointStream> {
        let stream = self
            .0
            .read()
            .await
            .stream_checkpoints(
                start_sequence_number,
                end_sequence_number,
                to_proto_transactions_filter(&transactions_filter),
                to_proto_events_filter(&events_filter),
                super::read_mask::<CheckpointResponseReadMask>(&read_mask),
            )
            .await?
            .into_inner();
        Ok(CheckpointStream(Mutex::new(stream)))
    }

    /// Stream checkpoints across a range of sequence numbers, skipping
    /// checkpoints with no data matching the filters.
    ///
    /// Unlike [`GrpcClient::stream_checkpoints`], the filters decide which
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
        read_mask = None,
        transactions_filter = None,
        events_filter = None,
        progress_interval_ms = None
    ))]
    pub async fn stream_checkpoints_filtered(
        &self,
        start_sequence_number: Option<u64>,
        end_sequence_number: Option<u64>,
        read_mask: Option<Vec<String>>,
        transactions_filter: Option<Arc<GrpcTransactionFilter>>,
        events_filter: Option<Arc<GrpcEventFilter>>,
        progress_interval_ms: Option<u32>,
    ) -> Result<FilteredCheckpointStream> {
        let stream = self
            .0
            .read()
            .await
            .stream_checkpoints_filtered(
                start_sequence_number,
                end_sequence_number,
                to_proto_transactions_filter(&transactions_filter),
                to_proto_events_filter(&events_filter),
                progress_interval_ms,
                super::read_mask::<CheckpointResponseReadMask>(&read_mask),
            )
            .await?
            .into_inner();
        Ok(FilteredCheckpointStream(Mutex::new(stream)))
    }
}
