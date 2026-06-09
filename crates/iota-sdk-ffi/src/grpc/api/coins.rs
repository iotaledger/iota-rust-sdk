// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Coins API implementation.

use crate::{
    error::Result,
    grpc::{client::GrpcClient, output_types::GrpcCoinInfo},
    types::move_core::StructTag,
};

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// Get information about a coin type, including its metadata, treasury,
    /// and regulated metadata.
    pub async fn get_coin_info(&self, coin_type: &StructTag) -> Result<GrpcCoinInfo> {
        (&self
            .0
            .read()
            .await
            .get_coin_info(coin_type.0.clone())
            .await?
            .into_inner())
            .try_into()
    }
}
