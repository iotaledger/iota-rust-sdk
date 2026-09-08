// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Health API implementation.

use iota_sdk::grpc_types::v1 as proto;

use crate::{error::Result, grpc::client::GrpcClient};

/// Health information about the node serving the gRPC service.
#[derive(uniffi::Record)]
pub struct HealthInfo {
    /// Checkpoint height of the most recently executed checkpoint.
    pub executed_checkpoint_height: Option<u64>,
    /// Estimated validator latency in milliseconds.
    pub estimated_validator_latency_ms: Option<u32>,
}

impl From<&proto::ledger_service::GetHealthResponse> for HealthInfo {
    fn from(value: &proto::ledger_service::GetHealthResponse) -> Self {
        Self {
            executed_checkpoint_height: value.executed_checkpoint_height,
            estimated_validator_latency_ms: value.estimated_validator_latency_ms,
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// Get the health of the node serving the gRPC service.
    ///
    /// If `threshold_ms` is provided, the server returns an `UNAVAILABLE`
    /// error when the most recently executed checkpoint is older than the
    /// threshold.
    #[uniffi::method(default(threshold_ms = None))]
    pub async fn health(&self, threshold_ms: Option<u64>) -> Result<HealthInfo> {
        Ok((&self.0.read().await.health(threshold_ms).await?.into_inner()).into())
    }
}
