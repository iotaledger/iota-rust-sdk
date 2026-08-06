// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Epochs API implementation.

use iota_sdk::grpc_client::read_mask_fields::EpochReadMask;

use crate::{
    error::Result,
    grpc::{client::GrpcClient, output_types::EpochInfo},
};

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// Get information about an epoch. If `epoch` is `None`, the current
    /// epoch is returned.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    #[uniffi::method(default(epoch = None, read_mask = None))]
    pub async fn get_epoch(
        &self,
        epoch: Option<u64>,
        read_mask: Option<Vec<String>>,
    ) -> Result<EpochInfo> {
        (&self
            .0
            .read()
            .await
            .get_epoch(epoch, super::read_mask::<EpochReadMask>(&read_mask))
            .await?
            .into_inner())
            .try_into()
    }

    /// Get the reference gas price of the current epoch, denominated in
    /// NANOS.
    pub async fn get_reference_gas_price(&self) -> Result<u64> {
        Ok(self
            .0
            .read()
            .await
            .get_reference_gas_price()
            .await?
            .into_inner())
    }
}
