// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Checkpoints API implementation.

use cynic::QueryBuilder;
use futures::Stream;
use iota_types::{CheckpointDigest, CheckpointSequenceNumber, CheckpointSummary};

use crate::{
    Client,
    error::{GraphQLError, GraphQLResult},
    pagination::{Direction, Page, PaginationFilter},
    query_types::{
        CheckpointArgs, CheckpointId, CheckpointQuery, CheckpointTotalTxQuery, CheckpointsArgs,
        CheckpointsQuery,
    },
    streams::stream_paginated_query,
};

impl Client {
    /// Get a stream of [`CheckpointSummary`]. Note that this will fetch all
    /// checkpoints which may trigger a lot of requests.
    pub fn checkpoints_stream(
        &self,
        streaming_direction: Direction,
    ) -> impl Stream<Item = GraphQLResult<CheckpointSummary>> + '_ {
        stream_paginated_query(move |filter| self.checkpoints(filter), streaming_direction)
    }

    /// Get the [`CheckpointSummary`] for a given checkpoint digest or
    /// checkpoint id. If none is provided, it will use the last known
    /// checkpoint id.
    pub async fn checkpoint(
        &self,
        digest: impl Into<Option<CheckpointDigest>>,
        seq_num: impl Into<Option<u64>>,
    ) -> GraphQLResult<Option<CheckpointSummary>> {
        let digest = digest.into();
        let seq_num = seq_num.into();
        if digest.is_some() && seq_num.is_some() {
            return Err(GraphQLError::InvalidArgument(
                "either digest or seq_num can be provided, but not both",
            ));
        }

        let operation = CheckpointQuery::build(CheckpointArgs {
            id: CheckpointId {
                digest: digest.map(|d| d.to_string()),
                sequence_number: seq_num,
            },
        });
        let response = self.run_query(&operation).await?;

        response.checkpoint.map(|c| c.try_into()).transpose()
    }

    /// Get a page of [`CheckpointSummary`] for the provided parameters.
    pub async fn checkpoints(
        &self,
        pagination_filter: PaginationFilter,
    ) -> GraphQLResult<Page<CheckpointSummary>> {
        let pagination = self.pagination_filter(pagination_filter).await;

        let operation = CheckpointsQuery::build(CheckpointsArgs {
            after: pagination.after.as_deref(),
            before: pagination.before.as_deref(),
            first: pagination.first,
            last: pagination.last,
        });
        let response = self.run_query(&operation).await?;

        let cc = response.checkpoints;
        let page_info = cc.page_info;
        let nodes = cc
            .nodes
            .into_iter()
            .map(|c| c.try_into())
            .collect::<GraphQLResult<Vec<CheckpointSummary>, _>>()?;

        Ok(Page::new(page_info, nodes))
    }

    /// Return the sequence number of the latest checkpoint that has been
    /// executed.
    pub async fn latest_checkpoint_sequence_number(
        &self,
    ) -> GraphQLResult<Option<CheckpointSequenceNumber>> {
        Ok(self
            .checkpoint(None, None)
            .await?
            .map(|c| c.sequence_number))
    }

    /// The total number of transaction blocks in the network by the end of the
    /// provided checkpoint digest.
    pub async fn total_transaction_blocks_by_digest(
        &self,
        digest: CheckpointDigest,
    ) -> GraphQLResult<Option<u64>> {
        self.internal_total_transaction_blocks(Some(digest.to_string()), None)
            .await
    }

    /// The total number of transaction blocks in the network by the end of the
    /// provided checkpoint sequence number.
    pub async fn total_transaction_blocks_by_seq_num(
        &self,
        seq_num: u64,
    ) -> GraphQLResult<Option<u64>> {
        self.internal_total_transaction_blocks(None, Some(seq_num))
            .await
    }

    /// The total number of transaction blocks in the network by the end of the
    /// last known checkpoint.
    pub async fn total_transaction_blocks(&self) -> GraphQLResult<Option<u64>> {
        self.internal_total_transaction_blocks(None, None).await
    }

    /// Internal function to get the total number of transaction blocks based on
    /// the provided checkpoint digest or sequence number.
    async fn internal_total_transaction_blocks(
        &self,
        digest: Option<String>,
        seq_num: Option<u64>,
    ) -> GraphQLResult<Option<u64>> {
        if digest.is_some() && seq_num.is_some() {
            return Err(GraphQLError::InvalidArgument(
                "either digest or seq_num can be provided, but not both",
            ));
        }

        let operation = CheckpointTotalTxQuery::build(CheckpointArgs {
            id: CheckpointId {
                digest,
                sequence_number: seq_num,
            },
        });
        let response = self.run_query(&operation).await?;

        Ok(response
            .checkpoint
            .and_then(|c| c.network_total_transactions))
    }
}

#[cfg(test)]
mod tests {
    use crate::{PaginationFilter, test_utils::test_client};

    #[test]
    fn checkpoints_query_forwards_pagination_arguments() {
        use cynic::QueryBuilder;

        use crate::query_types::{CheckpointsArgs, CheckpointsQuery};

        let operation = CheckpointsQuery::build(CheckpointsArgs {
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
            .checkpoint(None, None)
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
            .checkpoints(PaginationFilter::default())
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

    #[tokio::test]
    async fn test_latest_checkpoint_sequence_number_query() {
        let client = test_client();
        client
            .latest_checkpoint_sequence_number()
            .await
            .map_err(|e| {
                format!(
                    "Latest checkpoint sequence number query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_total_transaction_blocks() {
        let client = test_client();
        let total_transaction_blocks = client
            .total_transaction_blocks()
            .await
            .map_err(|e| {
                format!(
                    "Total transaction blocks query failed for {} network. Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
        assert!(total_transaction_blocks > 0);

        let checkpoint_seq_num = client
            .latest_checkpoint_sequence_number()
            .await
            .map_err(|e| {
                format!(
                    "Latest checkpoint sequence number query failed for {} network. Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
        let total_transaction_blocks_by_seq_num = client
            .total_transaction_blocks_by_seq_num(checkpoint_seq_num)
            .await
            .unwrap()
            .unwrap();
        assert!(
            total_transaction_blocks_by_seq_num >= total_transaction_blocks,
            "expected at least {total_transaction_blocks} transaction blocks, found {total_transaction_blocks_by_seq_num}"
        );

        let checkpoint = client
            .checkpoint(None, Some(checkpoint_seq_num))
            .await
            .unwrap()
            .unwrap();

        let total_transaction_blocks_by_digest = client
            .total_transaction_blocks_by_digest(checkpoint.digest())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            total_transaction_blocks_by_seq_num,
            total_transaction_blocks_by_digest
        );
    }
}
