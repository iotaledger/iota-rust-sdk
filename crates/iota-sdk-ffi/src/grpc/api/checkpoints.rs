// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Checkpoints API implementation.

use std::{pin::Pin, sync::Arc};

use futures::{Stream, StreamExt};
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
                super::read_mask(&read_mask),
                to_proto_transactions_filter(&transactions_filter),
                to_proto_events_filter(&events_filter),
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
                super::read_mask(&read_mask),
                to_proto_transactions_filter(&transactions_filter),
                to_proto_events_filter(&events_filter),
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
                super::read_mask(&read_mask),
                to_proto_transactions_filter(&transactions_filter),
                to_proto_events_filter(&events_filter),
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
                super::read_mask(&read_mask),
                to_proto_transactions_filter(&transactions_filter),
                to_proto_events_filter(&events_filter),
            )
            .await?
            .into_inner();
        Ok(CheckpointStream(Mutex::new(stream)))
    }
}
