// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Epoch API implementation.

use cynic::QueryBuilder;

use crate::{
    GraphQLClient,
    api::define_query,
    error::GraphQLResult,
    query_types::{Epoch, EpochArgs, EpochQueryFragment},
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
    pub fn epoch_number(mut self, epoch_number: impl Into<Option<u64>>) -> Self {
        self.epoch = epoch_number.into();
        self
    }

    async fn send(self) -> GraphQLResult<Option<Epoch>> {
        let operation = EpochQueryFragment::build(EpochArgs { id: self.epoch });
        let response = self.client.run_query(&operation).await?;

        Ok(response.epoch)
    }
}

impl GraphQLClient {
    /// Return the epoch information. Defaults to the last known epoch.
    pub fn epoch(&self) -> GetEpochQuery {
        GetEpochQuery {
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

        let vars = sent_variables("EpochQueryFragment", |client| async move {
            let _ = client.epoch().await;
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
}
