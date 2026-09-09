// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Coins API implementation.

use std::sync::Arc;

use crate::{
    error::Result,
    grpc::client::GrpcClient,
    types::{address::Address, coin::Coin, move_core::StructTag},
};

/// A page of coins returned by the gRPC server.
#[derive(uniffi::Record)]
pub struct GrpcCoinPage {
    /// The coins returned in the page.
    pub coins: Vec<Arc<Coin>>,
    /// Token to retrieve the next page. `None` when this is the last page.
    pub next_page_token: Option<Vec<u8>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// List a single page of coins owned by an address, optionally filtered
    /// by coin type (the inner type `T` of `Coin<T>`). If `coin_type` is
    /// `None`, coins of all types are returned.
    ///
    /// Pass the returned `next_page_token` back in to retrieve the next page.
    #[uniffi::method(default(coin_type = None, page_size = None, page_token = None))]
    pub async fn coins(
        &self,
        owner: &Address,
        coin_type: Option<Arc<StructTag>>,
        page_size: Option<u32>,
        page_token: Option<Vec<u8>>,
    ) -> Result<GrpcCoinPage> {
        let query = self.0.read().await.coins(
            **owner,
            coin_type.map(|coin_type| coin_type.0.clone()),
            page_size,
            page_token.map(Into::into),
        );
        let page = query.await?.into_inner();
        Ok(GrpcCoinPage {
            coins: page
                .items
                .into_iter()
                .map(Into::into)
                .map(Arc::new)
                .collect(),
            next_page_token: page.next_page_token.map(|token| token.to_vec()),
        })
    }

    /// List all coins owned by an address, optionally filtered by coin type
    /// (the inner type `T` of `Coin<T>`), auto-paginating up to `limit`
    /// coins. If `coin_type` is `None`, coins of all types are returned. If
    /// `limit` is `None`, all coins are returned.
    #[uniffi::method(default(coin_type = None, limit = None))]
    pub async fn all_coins(
        &self,
        owner: &Address,
        coin_type: Option<Arc<StructTag>>,
        limit: Option<u32>,
    ) -> Result<Vec<Arc<Coin>>> {
        let query = self.0.read().await.coins(
            **owner,
            coin_type.map(|coin_type| coin_type.0.clone()),
            None,
            None,
        );
        Ok(query
            .collect(limit)
            .await?
            .into_inner()
            .into_iter()
            .map(Into::into)
            .map(Arc::new)
            .collect())
    }
}
