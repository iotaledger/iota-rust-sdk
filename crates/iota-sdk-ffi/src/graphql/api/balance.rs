// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Balance API implementation.

use crate::{error::Result, graphql::client::GraphQLClient, types::address::Address};

#[uniffi::export(async_runtime = "tokio")]
impl GraphQLClient {
    /// Get the balance of all the coins owned by address for the provided coin
    /// type. Coin type will default to `0x2::coin::Coin<0x2::iota::IOTA>`
    /// if not provided.
    #[uniffi::method(default(coin_type = None))]
    pub async fn balance(
        &self,
        address: &Address,
        coin_type: Option<String>,
    ) -> Result<Option<u64>> {
        Ok(self.0.read().await.balance(**address, coin_type).await?)
    }
}
