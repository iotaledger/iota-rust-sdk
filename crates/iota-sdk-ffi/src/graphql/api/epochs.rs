// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Epoch API implementation.

use iota_sdk::graphql_client::{
    GetEpochQuery, GetEpochTotalCheckpointsQuery, GetEpochTotalTransactionBlocksQuery,
};

use crate::{
    error::Result,
    graphql::{client::GraphQLClient, query_types::GraphQLEpoch},
    helpers::SetIfSome,
};

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl GraphQLClient {
    /// Return the epoch information for the provided epoch. If no epoch is
    /// provided, it will return the last known epoch.
    #[uniffi::method(default(epoch = None))]
    pub async fn epoch(&self, epoch: Option<u64>) -> Result<Option<GraphQLEpoch>> {
        Ok(self
            .client()
            .epoch()
            .set_if_some(epoch, GetEpochQuery::epoch_number)
            .await?
            .map(Into::into))
    }

    /// Return the number of checkpoints in this epoch. This will return
    /// `Ok(None)` if the epoch requested is not available in the GraphQL
    /// service (e.g., due to pruning).
    #[uniffi::method(default(epoch = None))]
    pub async fn epoch_total_checkpoints(&self, epoch: Option<u64>) -> Result<Option<u64>> {
        Ok(self
            .client()
            .epoch_total_checkpoints()
            .set_if_some(epoch, GetEpochTotalCheckpointsQuery::epoch_number)
            .await?)
    }

    /// Return the number of transaction blocks in this epoch. This will return
    /// `Ok(None)` if the epoch requested is not available in the GraphQL
    /// service (e.g., due to pruning).
    #[uniffi::method(default(epoch = None))]
    pub async fn epoch_total_transaction_blocks(&self, epoch: Option<u64>) -> Result<Option<u64>> {
        Ok(self
            .client()
            .epoch_total_transaction_blocks()
            .set_if_some(epoch, GetEpochTotalTransactionBlocksQuery::epoch_number)
            .await?)
    }
}
