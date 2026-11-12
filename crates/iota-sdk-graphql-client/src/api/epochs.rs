// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Epoch API implementation.

use cynic::QueryBuilder;

use crate::{
    GraphQLClient,
    api::define_query,
    error::GraphQLResult,
    query_types::{Epoch, EpochArgs, EpochQueryFragment, EpochSummaryQueryFragment},
};

define_query! {
    /// Query for [`GraphQLClient::epoch`]. Await it to send the request.
    pub struct GetEpochQuery {
        client: GraphQLClient,
        epoch: Option<u64>,
    }
    output: GraphQLResult<Option<Epoch>>;
}

impl GetEpochQuery {
    /// Set the epoch number. Defaults to the last known epoch.
    pub fn epoch_number(mut self, epoch_number: u64) -> Self {
        self.epoch = Some(epoch_number);
        self
    }

    async fn send(self) -> GraphQLResult<Option<Epoch>> {
        let operation = EpochQueryFragment::build(EpochArgs { id: self.epoch });
        let response = self.client.run_query(&operation).await?;

        Ok(response.epoch)
    }
}

define_query! {
    /// Query for [`GraphQLClient::epoch_total_checkpoints`]. Await it to send
    /// the request.
    pub struct GetEpochTotalCheckpointsQuery {
        client: GraphQLClient,
        epoch: Option<u64>,
    }
    output: GraphQLResult<Option<u64>>;
}

impl GetEpochTotalCheckpointsQuery {
    /// Set the epoch number. Defaults to the last known epoch.
    pub fn epoch_number(mut self, epoch_number: u64) -> Self {
        self.epoch = Some(epoch_number);
        self
    }

    async fn send(self) -> GraphQLResult<Option<u64>> {
        let response = self.client.epoch_summary(self.epoch).await?;

        Ok(response.epoch.and_then(|e| e.total_checkpoints))
    }
}

define_query! {
    /// Query for [`GraphQLClient::epoch_total_transaction_blocks`]. Await it to
    /// send the request.
    pub struct GetEpochTotalTransactionBlocksQuery {
        client: GraphQLClient,
        epoch: Option<u64>,
    }
    output: GraphQLResult<Option<u64>>;
}

impl GetEpochTotalTransactionBlocksQuery {
    /// Set the epoch number. Defaults to the last known epoch.
    pub fn epoch_number(mut self, epoch_number: u64) -> Self {
        self.epoch = Some(epoch_number);
        self
    }

    async fn send(self) -> GraphQLResult<Option<u64>> {
        let response = self.client.epoch_summary(self.epoch).await?;

        Ok(response.epoch.and_then(|e| e.total_transactions))
    }
}

impl GraphQLClient {
    /// Internal method for getting the epoch summary that is called in a few
    /// other APIs for convenience.
    pub(crate) async fn epoch_summary(
        &self,
        epoch: Option<u64>,
    ) -> GraphQLResult<EpochSummaryQueryFragment> {
        let operation = EpochSummaryQueryFragment::build(EpochArgs { id: epoch });
        self.run_query(&operation).await
    }

    /// Return the epoch information. Defaults to the last known epoch.
    pub fn epoch(&self) -> GetEpochQuery {
        GetEpochQuery {
            client: self.clone(),
            epoch: None,
        }
    }

    /// Return the number of checkpoints in an epoch. Resolves to `None` if the
    /// epoch requested is not available in the GraphQL service (e.g., due to
    /// pruning).
    pub fn epoch_total_checkpoints(&self) -> GetEpochTotalCheckpointsQuery {
        GetEpochTotalCheckpointsQuery {
            client: self.clone(),
            epoch: None,
        }
    }

    /// Return the number of transaction blocks in an epoch. Resolves to `None`
    /// if the epoch requested is not available in the GraphQL service (e.g.,
    /// due to pruning).
    pub fn epoch_total_transaction_blocks(&self) -> GetEpochTotalTransactionBlocksQuery {
        GetEpochTotalTransactionBlocksQuery {
            client: self.clone(),
            epoch: None,
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use crate::test_utils::{sent_variables, test_client};

    #[tokio::test]
    async fn epoch_queries_send_the_epoch() {
        let vars = sent_variables("EpochQueryFragment", |client| async move {
            let _ = client.epoch().epoch_number(3).await;
        })
        .await;
        assert_eq!(vars["id"], 3);

        let vars = sent_variables("EpochSummaryQueryFragment", |client| async move {
            let _ = client.epoch_total_checkpoints().epoch_number(4).await;
        })
        .await;
        assert_eq!(vars["id"], 4);

        let vars = sent_variables("EpochSummaryQueryFragment", |client| async move {
            let _ = client
                .epoch_total_transaction_blocks()
                .epoch_number(5)
                .await;
        })
        .await;
        assert_eq!(vars["id"], 5);

        let vars = sent_variables("EpochQueryFragment", |client| async move {
            let _ = client.epoch().await;
        })
        .await;
        assert!(vars["id"].is_null());

        let vars = sent_variables("EpochSummaryQueryFragment", |client| async move {
            let _ = client.epoch_total_checkpoints().await;
        })
        .await;
        assert!(vars["id"].is_null());

        let vars = sent_variables("EpochSummaryQueryFragment", |client| async move {
            let _ = client.epoch_total_transaction_blocks().await;
        })
        .await;
        assert!(vars["id"].is_null());
    }

    #[tokio::test]
    async fn test_epoch_query() {
        let client = test_client();
        client
            .epoch()
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
            .epoch_total_checkpoints()
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
            .epoch_total_transaction_blocks()
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
