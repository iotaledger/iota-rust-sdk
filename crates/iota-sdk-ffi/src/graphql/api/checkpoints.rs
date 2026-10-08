// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Checkpoints API implementation.

use std::sync::Arc;

use crate::{
    error::Result,
    graphql::{
        client::GraphQLClient, pagination::GraphQLCheckpointSummaryPage,
        query_types::GraphQLPaginationFilter,
    },
    types::{checkpoint::CheckpointSummary, digest::CheckpointDigest},
};

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl GraphQLClient {
    /// Get the `CheckpointSummary` for a given checkpoint digest or
    /// checkpoint id. If none is provided, it will use the last known
    /// checkpoint id.
    #[uniffi::method(default(digest = None, sequence_number = None))]
    pub async fn checkpoint(
        &self,
        digest: Option<Arc<CheckpointDigest>>,
        sequence_number: Option<u64>,
    ) -> Result<Option<Arc<CheckpointSummary>>> {
        let client = self.client();
        let query = match (digest, sequence_number) {
            (None, None) => client.checkpoint(),
            (Some(digest), None) => client.checkpoint_by_digest(**digest),
            (None, Some(sequence_number)) => client.checkpoint_by_sequence_number(sequence_number),
            (Some(_), Some(_)) => Err(iota_sdk::graphql_client::GraphQLError::InvalidArgument(
                "either digest or sequence_number can be provided, but not both",
            ))?,
        };
        Ok(query.await?.map(Into::into).map(Arc::new))
    }

    /// Get a page of `CheckpointSummary` for the provided parameters.
    #[uniffi::method(default(pagination_filter = None))]
    pub async fn checkpoints(
        &self,
        pagination_filter: Option<GraphQLPaginationFilter>,
    ) -> Result<GraphQLCheckpointSummaryPage> {
        Ok(self
            .client()
            .checkpoints()
            .pagination(pagination_filter.map(Into::into).unwrap_or_default())
            .await?
            .map(Into::into)
            .into())
    }
}
