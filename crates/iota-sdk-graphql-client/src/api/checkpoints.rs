// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Checkpoints API implementation.

use cynic::QueryBuilder;
use futures::Stream;
use iota_types::{CheckpointDigest, CheckpointSummary};

use crate::{
    GraphQLClient,
    api::define_query,
    error::GraphQLResult,
    pagination::{Direction, Page, PaginationFilter, PaginationFilterResponse},
    query_types::{
        CheckpointArgs, CheckpointId, CheckpointQueryFragment, CheckpointsArgs,
        CheckpointsQueryFragment,
    },
    streams::stream_paginated_query,
};

define_query! {
    /// Query for [`GraphQLClient::checkpoints`]. Await it to send the request.
    pub struct ListCheckpointsQuery {
        client: GraphQLClient,
        pagination: PaginationFilter,
    }
    output: GraphQLResult<Page<CheckpointSummary>>;
}

impl ListCheckpointsQuery {
    /// Set the page to fetch.
    pub fn pagination(mut self, pagination: PaginationFilter) -> Self {
        self.pagination = pagination;
        self
    }

    fn operation<'a>(
        pagination: &'a PaginationFilterResponse,
    ) -> cynic::Operation<CheckpointsQueryFragment, CheckpointsArgs<'a>> {
        CheckpointsQueryFragment::build(CheckpointsArgs {
            after: pagination.after.as_deref(),
            before: pagination.before.as_deref(),
            first: pagination.first,
            last: pagination.last,
        })
    }

    async fn send(self) -> GraphQLResult<Page<CheckpointSummary>> {
        let Self { client, pagination } = self;
        let pagination = client.pagination_filter(pagination).await;
        let response = client.run_query(&Self::operation(&pagination)).await?;

        let cc = response.checkpoints;
        let page_info = cc.page_info;
        let nodes = cc
            .nodes
            .into_iter()
            .map(|c| c.try_into())
            .collect::<GraphQLResult<Vec<_>>>()?;

        Ok(Page::new(page_info, nodes))
    }
}

define_query! {
    /// Query for [`GraphQLClient::checkpoint`],
    /// [`GraphQLClient::checkpoint_by_digest`] and
    /// [`GraphQLClient::checkpoint_by_sequence_number`]. Await it to send the
    /// request.
    pub struct GetCheckpointQuery {
        client: GraphQLClient,
        digest: Option<CheckpointDigest>,
        sequence_number: Option<u64>,
    }
    output: GraphQLResult<Option<CheckpointSummary>>;
}

impl GetCheckpointQuery {
    async fn send(self) -> GraphQLResult<Option<CheckpointSummary>> {
        let operation = CheckpointQueryFragment::build(CheckpointArgs {
            id: CheckpointId {
                digest: self.digest.map(|d| d.to_string()),
                sequence_number: self.sequence_number,
            },
        });
        let response = self.client.run_query(&operation).await?;

        response.checkpoint.map(|c| c.try_into()).transpose()
    }
}

impl GraphQLClient {
    /// Get a stream of [`CheckpointSummary`]. Note that this will fetch all
    /// checkpoints which may trigger a lot of requests.
    pub fn checkpoints_stream(
        &self,
        streaming_direction: Direction,
    ) -> impl Stream<Item = GraphQLResult<CheckpointSummary>> + '_ {
        stream_paginated_query(
            move |filter| self.checkpoints().pagination(filter).into_future(),
            streaming_direction,
        )
    }

    /// Get the [`CheckpointSummary`] of the last known checkpoint.
    pub fn checkpoint(&self) -> GetCheckpointQuery {
        GetCheckpointQuery {
            client: self.clone(),
            digest: None,
            sequence_number: None,
        }
    }

    /// Get the [`CheckpointSummary`] for the given checkpoint digest.
    pub fn checkpoint_by_digest(&self, digest: CheckpointDigest) -> GetCheckpointQuery {
        GetCheckpointQuery {
            client: self.clone(),
            digest: Some(digest),
            sequence_number: None,
        }
    }

    /// Get the [`CheckpointSummary`] for the given checkpoint sequence number.
    pub fn checkpoint_by_sequence_number(&self, sequence_number: u64) -> GetCheckpointQuery {
        GetCheckpointQuery {
            client: self.clone(),
            digest: None,
            sequence_number: Some(sequence_number),
        }
    }

    /// Get a page of [`CheckpointSummary`].
    pub fn checkpoints(&self) -> ListCheckpointsQuery {
        ListCheckpointsQuery {
            client: self.clone(),
            pagination: PaginationFilter::default(),
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use iota_types::CheckpointDigest;

    use crate::test_utils::{
        assert_backward_page, assert_forward_page, backward_page, forward_page, sent_variables,
        test_client,
    };

    #[tokio::test]
    async fn checkpoint_sends_the_digest_or_sequence_number() {
        let vars = sent_variables("CheckpointQueryFragment", |client| async move {
            let _ = client.checkpoint_by_sequence_number(7).await;
        })
        .await;
        assert_eq!(vars["id"]["sequenceNumber"], 7);
        assert!(vars["id"]["digest"].is_null());

        let digest = CheckpointDigest::ZERO;
        let vars = sent_variables("CheckpointQueryFragment", |client| async move {
            let _ = client.checkpoint_by_digest(digest).await;
        })
        .await;
        assert_eq!(vars["id"]["digest"], digest.to_string());
        assert!(vars["id"]["sequenceNumber"].is_null());

        let vars = sent_variables("CheckpointQueryFragment", |client| async move {
            let _ = client.checkpoint().await;
        })
        .await;
        assert!(vars["id"]["digest"].is_null());
        assert!(vars["id"]["sequenceNumber"].is_null());
    }

    #[tokio::test]
    async fn checkpoints_sends_the_pagination() {
        let vars = sent_variables("CheckpointsQueryFragment", |client| async move {
            let _ = client.checkpoints().pagination(backward_page()).await;
        })
        .await;
        assert_backward_page(&vars);

        let vars = sent_variables("CheckpointsQueryFragment", |client| async move {
            let _ = client.checkpoints().pagination(forward_page()).await;
        })
        .await;
        assert_forward_page(&vars);
    }

    #[test]
    fn checkpoints_query_forwards_pagination_arguments() {
        use cynic::QueryBuilder;

        use crate::query_types::{CheckpointsArgs, CheckpointsQueryFragment};

        let operation = CheckpointsQueryFragment::build(CheckpointsArgs {
            first: Some(10),
            after: None,
            last: None,
            before: None,
        });
        for arg in ["first:", "after:", "last:", "before:"] {
            assert!(
                operation.query.contains(arg),
                "checkpoints query is missing the `{arg}` argument:\n{}",
                operation.query
            );
        }
    }

    #[tokio::test]
    async fn test_checkpoint_query() {
        let client = test_client();
        client
            .checkpoint()
            .await
            .map_err(|e| {
                format!(
                    "Checkpoint query failed for {} network: Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_checkpoints_query() {
        let client = test_client();
        let cs = client
            .checkpoints()
            .await
            .map_err(|e| {
                format!(
                    "Checkpoints query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap();

        assert!(
            !cs.is_empty(),
            "Checkpoints query returned no data for {} network",
            client.rpc_server()
        );
    }
}
