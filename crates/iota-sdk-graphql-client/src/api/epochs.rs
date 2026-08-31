// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Epoch API implementation.

use cynic::QueryBuilder;

use crate::{
    Client,
    error::GraphQLResult,
    query_types::{Epoch, EpochArgs, EpochQuery, EpochSummaryQuery},
};

impl Client {
    /// Internal method for getting the epoch summary that is called in a few
    /// other APIs for convenience.
    pub(crate) async fn epoch_summary(
        &self,
        epoch: Option<u64>,
    ) -> GraphQLResult<EpochSummaryQuery> {
        let operation = EpochSummaryQuery::build(EpochArgs { id: epoch });
        self.run_query(&operation).await
    }

    /// Return the epoch information for the provided epoch. If no epoch is
    /// provided, it will return the last known epoch.
    pub async fn epoch(&self, epoch: impl Into<Option<u64>>) -> GraphQLResult<Option<Epoch>> {
        let operation = EpochQuery::build(EpochArgs { id: epoch.into() });
        let response = self.run_query(&operation).await?;

        Ok(response.epoch)
    }

    /// Return the number of checkpoints in this epoch. This will return
    /// `Ok(None)` if the epoch requested is not available in the GraphQL
    /// service (e.g., due to pruning).
    pub async fn epoch_total_checkpoints(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> GraphQLResult<Option<u64>> {
        let response = self.epoch_summary(epoch.into()).await?;

        Ok(response.epoch.and_then(|e| e.total_checkpoints))
    }

    /// Return the number of transaction blocks in this epoch. This will return
    /// `Ok(None)` if the epoch requested is not available in the GraphQL
    /// service (e.g., due to pruning).
    pub async fn epoch_total_transaction_blocks(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> GraphQLResult<Option<u64>> {
        let response = self.epoch_summary(epoch.into()).await?;

        Ok(response.epoch.and_then(|e| e.total_transactions))
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::test_client;

    #[tokio::test]
    async fn test_epoch_query() {
        let client = test_client();
        client
            .epoch(None)
            .await
            .map_err(|e| {
                format!(
                    "Epoch query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_epoch_total_checkpoints_query() {
        let client = test_client();
        client
            .epoch_total_checkpoints(None)
            .await
            .map_err(|e| {
                format!(
                    "Epoch total checkpoints query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_epoch_total_transaction_blocks_query() {
        let client = test_client();
        client
            .epoch_total_transaction_blocks(None)
            .await
            .map_err(|e| {
                format!(
                    "Epoch total transaction blocks query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
    }

    #[tokio::test]
    async fn test_epoch_summary_query() {
        let client = test_client();
        client
            .epoch_summary(None)
            .await
            .map_err(|e| {
                format!(
                    "Epoch summary query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
    }
}
