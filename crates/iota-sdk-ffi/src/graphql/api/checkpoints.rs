// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Checkpoints API implementation.

use std::sync::Arc;

use iota_sdk::{graphql_client::pagination::PaginationFilter, types::CheckpointSequenceNumber};

use crate::{
    error::Result,
    graphql::{client::GraphQLClient, pagination::CheckpointSummaryPage},
    types::{checkpoint::CheckpointSummary, digest::Digest},
};

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl GraphQLClient {
    /// Get the `CheckpointSummary` for a given checkpoint digest or
    /// checkpoint id. If none is provided, it will use the last known
    /// checkpoint id.
    #[uniffi::method(default(digest = None, seq_num = None))]
    pub async fn checkpoint(
        &self,
        digest: Option<Arc<Digest>>,
        seq_num: Option<u64>,
    ) -> Result<Option<Arc<CheckpointSummary>>> {
        Ok(self
            .0
            .read()
            .await
            .checkpoint(digest.map(|d| **d), seq_num)
            .await?
            .map(Into::into)
            .map(Arc::new))
    }

    /// Get a page of `CheckpointSummary` for the provided parameters.
    #[uniffi::method(default(pagination_filter = None))]
    pub async fn checkpoints(
        &self,
        pagination_filter: Option<PaginationFilter>,
    ) -> Result<CheckpointSummaryPage> {
        Ok(self
            .0
            .read()
            .await
            .checkpoints(pagination_filter.unwrap_or_default())
            .await?
            .map(Into::into)
            .into())
    }

    /// Return the sequence number of the latest checkpoint that has been
    /// executed.
    pub async fn latest_checkpoint_sequence_number(
        &self,
    ) -> Result<Option<CheckpointSequenceNumber>> {
        Ok(self
            .0
            .read()
            .await
            .latest_checkpoint_sequence_number()
            .await?)
    }

    /// The total number of transaction blocks in the network by the end of the
    /// provided checkpoint digest.
    pub async fn total_transaction_blocks_by_digest(&self, digest: &Digest) -> Result<Option<u64>> {
        Ok(self
            .0
            .read()
            .await
            .total_transaction_blocks_by_digest(**digest)
            .await?)
    }

    /// The total number of transaction blocks in the network by the end of the
    /// provided checkpoint sequence number.
    pub async fn total_transaction_blocks_by_seq_num(&self, seq_num: u64) -> Result<Option<u64>> {
        Ok(self
            .0
            .read()
            .await
            .total_transaction_blocks_by_seq_num(seq_num)
            .await?)
    }

    /// The total number of transaction blocks in the network by the end of the
    /// last known checkpoint.
    pub async fn total_transaction_blocks(&self) -> Result<Option<u64>> {
        Ok(self.0.read().await.total_transaction_blocks().await?)
    }
}
