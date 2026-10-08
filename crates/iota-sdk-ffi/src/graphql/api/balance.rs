// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Balance API implementation.

use iota_sdk::graphql_client::GetBalanceQuery;

use crate::{
    error::Result, graphql::client::GraphQLClient, helpers::SetIfSome, types::address::Address,
};

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl GraphQLClient {
    /// Get the balance of all the coins owned by address for the provided coin
    /// type. Coin type will default to `0x2::iota::IOTA` if not provided.
    #[uniffi::method(default(coin_type = None))]
    pub async fn balance(
        &self,
        address: &Address,
        coin_type: Option<String>,
    ) -> Result<Option<u64>> {
        Ok(self
            .client()
            .balance(**address)
            .set_if_some(coin_type, GetBalanceQuery::coin_type)
            .await?)
    }
}
