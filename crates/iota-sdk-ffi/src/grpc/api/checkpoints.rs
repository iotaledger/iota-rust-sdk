// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Checkpoints API implementation.

use crate::{
    error::Result,
    grpc::{client::GrpcClient, output_types::CheckpointResponse},
    types::digest::CheckpointDigest,
};

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// Get the latest checkpoint.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    /// If `None`, only the checkpoint summary is returned.
    #[uniffi::method(default(read_mask = None))]
    pub async fn get_checkpoint_latest(
        &self,
        read_mask: Option<Vec<String>>,
    ) -> Result<CheckpointResponse> {
        (&self
            .0
            .read()
            .await
            .get_checkpoint_latest(super::read_mask(&read_mask), None, None)
            .await?
            .into_inner())
            .try_into()
    }

    /// Get a checkpoint by its sequence number.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    /// If `None`, only the checkpoint summary is returned.
    #[uniffi::method(default(read_mask = None))]
    pub async fn get_checkpoint_by_sequence_number(
        &self,
        sequence_number: u64,
        read_mask: Option<Vec<String>>,
    ) -> Result<CheckpointResponse> {
        (&self
            .0
            .read()
            .await
            .get_checkpoint_by_sequence_number(
                sequence_number,
                super::read_mask(&read_mask),
                None,
                None,
            )
            .await?
            .into_inner())
            .try_into()
    }

    /// Get a checkpoint by its digest.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    /// If `None`, only the checkpoint summary is returned.
    #[uniffi::method(default(read_mask = None))]
    pub async fn get_checkpoint_by_digest(
        &self,
        digest: &CheckpointDigest,
        read_mask: Option<Vec<String>>,
    ) -> Result<CheckpointResponse> {
        (&self
            .0
            .read()
            .await
            .get_checkpoint_by_digest(**digest, super::read_mask(&read_mask), None, None)
            .await?
            .into_inner())
            .try_into()
    }
}
