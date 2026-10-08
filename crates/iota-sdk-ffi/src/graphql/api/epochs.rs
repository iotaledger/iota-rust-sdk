// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Epoch API implementation.

use crate::{
    error::Result,
    graphql::{client::GraphQLClient, query_types::GraphQLEpoch},
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
            .epoch_number(epoch)
            .await?
            .map(Into::into))
    }
}
