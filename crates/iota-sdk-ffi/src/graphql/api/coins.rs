// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Coin API implementation.

use std::sync::Arc;

use iota_sdk::graphql_client::pagination::PaginationFilter;

use crate::{
    error::Result,
    graphql::{client::GraphQLClient, pagination::CoinPage, query_types::CoinMetadata},
    types::{address::Address, move_core::StructTag},
};

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl GraphQLClient {
    /// Get the list of coins for the specified address.
    ///
    /// If `coin_type` is not provided, all coins will be returned. For IOTA
    /// coins, pass in the coin type: `0x2::iota::IOTA`.
    #[uniffi::method(default(pagination_filter = None, coin_type = None))]
    pub async fn coins(
        &self,
        owner: &Address,
        pagination_filter: Option<PaginationFilter>,
        coin_type: Option<Arc<StructTag>>,
    ) -> Result<CoinPage> {
        Ok(self
            .0
            .read()
            .await
            .coins(
                **owner,
                coin_type.map(|t| t.0.clone()),
                pagination_filter.unwrap_or_default(),
            )
            .await?
            .map(Into::into)
            .into())
    }

    /// Get the list of gas coins for the specified address.
    #[uniffi::method(default(pagination_filter = None))]
    pub async fn gas_coins(
        &self,
        owner: &Address,
        pagination_filter: Option<PaginationFilter>,
    ) -> Result<CoinPage> {
        Ok(self
            .0
            .read()
            .await
            .gas_coins(**owner, pagination_filter.unwrap_or_default())
            .await?
            .map(Into::into)
            .into())
    }

    /// Get the coin metadata for the coin type.
    pub async fn coin_metadata(&self, coin_type: &str) -> Result<Option<CoinMetadata>> {
        Ok(self
            .0
            .read()
            .await
            .coin_metadata(coin_type)
            .await?
            .map(Into::into))
    }

    /// Get total supply for the coin type.
    pub async fn total_supply(&self, coin_type: &str) -> Result<Option<u64>> {
        Ok(self.0.read().await.total_supply(coin_type).await?)
    }
}
