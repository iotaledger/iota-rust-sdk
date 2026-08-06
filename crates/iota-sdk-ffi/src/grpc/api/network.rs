// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Network information API implementation.

use iota_sdk::grpc_client::read_mask_fields::ServiceInfoReadMask;

use crate::{
    error::Result,
    grpc::{
        client::GrpcClient,
        output_types::{HealthInfo, ServiceInfo},
    },
};

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// Get the health of the node serving the gRPC service.
    ///
    /// If `threshold_ms` is provided, the server returns an `UNAVAILABLE`
    /// error when the most recently executed checkpoint is older than the
    /// threshold.
    #[uniffi::method(default(threshold_ms = None))]
    pub async fn get_health(&self, threshold_ms: Option<u64>) -> Result<HealthInfo> {
        Ok((&self
            .0
            .read()
            .await
            .get_health(threshold_ms)
            .await?
            .into_inner())
            .into())
    }

    /// Get information about the gRPC service and the node serving it.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    #[uniffi::method(default(read_mask = None))]
    pub async fn get_service_info(&self, read_mask: Option<Vec<String>>) -> Result<ServiceInfo> {
        (&self
            .0
            .read()
            .await
            .get_service_info(super::read_mask::<ServiceInfoReadMask>(&read_mask))
            .await?
            .into_inner())
            .try_into()
    }
}
