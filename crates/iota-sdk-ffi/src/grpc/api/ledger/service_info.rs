// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Service info API implementation.

use std::sync::Arc;

use iota_sdk::{
    grpc_client::read_mask_fields::ServiceInfoReadMask,
    grpc_types::{proto::proto_to_timestamp_ms, v1 as proto},
};

use crate::{
    error::{Result, SdkFfiError},
    grpc::client::GrpcClient,
    types::digest::Digest,
};

/// Information about the gRPC service and the node serving it.
#[derive(uniffi::Record)]
pub struct ServiceInfo {
    /// The chain identifier of the chain that the node is on, which is the
    /// digest of the genesis checkpoint.
    pub chain_id: Option<Arc<Digest>>,
    /// Human-readable name of the chain that the node is on.
    pub chain: Option<String>,
    /// Current epoch of the node based on its highest executed checkpoint.
    pub epoch: Option<u64>,
    /// Checkpoint height of the most recently executed checkpoint.
    pub executed_checkpoint_height: Option<u64>,
    /// Unix timestamp in milliseconds of the most recently executed
    /// checkpoint.
    pub executed_checkpoint_timestamp_ms: Option<u64>,
    /// The lowest checkpoint for which checkpoints and transaction data are
    /// available.
    pub lowest_available_checkpoint: Option<u64>,
    /// The lowest checkpoint for which object data is available.
    pub lowest_available_checkpoint_objects: Option<u64>,
    /// Software version of the service.
    pub server_version: Option<String>,
}

impl TryFrom<&proto::ledger_service::GetServiceInfoResponse> for ServiceInfo {
    type Error = SdkFfiError;

    fn try_from(value: &proto::ledger_service::GetServiceInfoResponse) -> Result<Self> {
        Ok(Self {
            chain_id: value
                .chain_id
                .as_ref()
                .map(iota_sdk::types::Digest::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            chain: value.chain.clone(),
            epoch: value.epoch,
            executed_checkpoint_height: value.executed_checkpoint_height,
            executed_checkpoint_timestamp_ms: value
                .executed_checkpoint_timestamp
                .map(proto_to_timestamp_ms)
                .transpose()?,
            lowest_available_checkpoint: value.lowest_available_checkpoint,
            lowest_available_checkpoint_objects: value.lowest_available_checkpoint_objects,
            server_version: value.server.clone(),
        })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// Get information about the gRPC service and the node serving it.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    #[uniffi::method(default(read_mask = None))]
    pub async fn service_info(&self, read_mask: Option<Vec<String>>) -> Result<ServiceInfo> {
        (&self
            .client()
            .service_info(crate::grpc::api::read_mask::<ServiceInfoReadMask>(
                &read_mask,
            ))
            .await?
            .into_inner())
            .try_into()
    }
}
