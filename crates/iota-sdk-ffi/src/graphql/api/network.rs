// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Network API implementation.

use crate::{
    error::Result,
    graphql::{
        client::GraphQLClient,
        pagination::GraphQLValidatorPage,
        query_types::{GraphQLPaginationFilter, GraphQLProtocolConfigs},
    },
};

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl GraphQLClient {
    /// Get the chain identifier.
    pub async fn chain_id(&self) -> Result<String> {
        Ok(self.client().chain_id().await?)
    }

    /// Get the reference gas price for the provided epoch or the last known one
    /// if no epoch is provided.
    ///
    /// This will return `Ok(None)` if the epoch requested is not available in
    /// the GraphQL service (e.g., due to pruning).
    #[uniffi::method(default(epoch = None))]
    pub async fn reference_gas_price(&self, epoch: Option<u64>) -> Result<Option<u64>> {
        Ok(self.client().reference_gas_price(epoch).await?)
    }

    /// Get the protocol configuration.
    #[uniffi::method(default(version = None))]
    pub async fn protocol_config(&self, version: Option<u64>) -> Result<GraphQLProtocolConfigs> {
        Ok(self.client().protocol_config(version).await?.into())
    }

    /// Get the list of active validators for the provided epoch, including
    /// related metadata. If no epoch is provided, it will return the active
    /// validators for the current epoch.
    #[uniffi::method(default(epoch = None, pagination_filter = None))]
    pub async fn active_validators(
        &self,
        epoch: Option<u64>,
        pagination_filter: Option<GraphQLPaginationFilter>,
    ) -> Result<GraphQLValidatorPage> {
        Ok(self
            .client()
            .active_validators(epoch, pagination_filter.map(Into::into).unwrap_or_default())
            .await?
            .map(Into::into)
            .into())
    }
}
