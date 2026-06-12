// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Epoch API implementation.

use crate::{
    error::Result,
    graphql::{client::GraphQLClient, query_types::Epoch},
};

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl GraphQLClient {
    /// Return the epoch information for the provided epoch. If no epoch is
    /// provided, it will return the last known epoch.
    #[uniffi::method(default(epoch = None))]
    pub async fn epoch(&self, epoch: Option<u64>) -> Result<Option<Epoch>> {
        Ok(self.0.read().await.epoch(epoch).await?.map(Into::into))
    }

    /// Return the number of checkpoints in this epoch. This will return
    /// `Ok(None)` if the epoch requested is not available in the GraphQL
    /// service (e.g., due to pruning).
    #[uniffi::method(default(epoch = None))]
    pub async fn epoch_total_checkpoints(&self, epoch: Option<u64>) -> Result<Option<u64>> {
        Ok(self.0.read().await.epoch_total_checkpoints(epoch).await?)
    }

    /// Return the number of transaction blocks in this epoch. This will return
    /// `Ok(None)` if the epoch requested is not available in the GraphQL
    /// service (e.g., due to pruning).
    #[uniffi::method(default(epoch = None))]
    pub async fn epoch_total_transaction_blocks(&self, epoch: Option<u64>) -> Result<Option<u64>> {
        Ok(self
            .0
            .read()
            .await
            .epoch_total_transaction_blocks(epoch)
            .await?)
    }
}
