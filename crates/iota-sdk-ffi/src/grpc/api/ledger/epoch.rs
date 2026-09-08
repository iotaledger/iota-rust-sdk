// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Epoch API implementation.

use std::{collections::HashMap, sync::Arc};

use iota_sdk::{
    grpc_client::read_mask_fields::EpochReadMask,
    grpc_types::{proto::proto_to_timestamp_ms, v1 as proto},
};

use crate::{
    error::{Result, SdkFfiError},
    grpc::client::GrpcClient,
    types::validator::ValidatorCommittee,
};

/// The protocol config of an epoch.
#[derive(uniffi::Record)]
pub struct GrpcProtocolConfig {
    /// The protocol version.
    pub protocol_version: Option<u64>,
    /// Map of feature flags to their status.
    pub feature_flags: HashMap<String, bool>,
    /// Map of attribute names to their values.
    pub attributes: HashMap<String, String>,
}

impl From<&proto::epoch::ProtocolConfig> for GrpcProtocolConfig {
    fn from(value: &proto::epoch::ProtocolConfig) -> Self {
        Self {
            protocol_version: value.protocol_version,
            feature_flags: value
                .feature_flags
                .as_ref()
                .map(|flags| flags.flags.clone().into_iter().collect())
                .unwrap_or_default(),
            attributes: value
                .attributes
                .as_ref()
                .map(|attributes| attributes.attributes.clone().into_iter().collect())
                .unwrap_or_default(),
        }
    }
}

/// Information about an epoch.
#[derive(uniffi::Record)]
pub struct EpochInfo {
    /// The epoch id.
    pub epoch: Option<u64>,
    /// The committee governing the epoch.
    pub committee: Option<Arc<ValidatorCommittee>>,
    /// Snapshot of IOTA's `SystemState` as BCS, at the beginning of the epoch
    /// for past epochs, or the current state for the current epoch.
    pub system_state_bcs: Option<Vec<u8>>,
    /// The first checkpoint sequence number of the epoch.
    pub first_checkpoint: Option<u64>,
    /// The last checkpoint sequence number of the epoch.
    pub last_checkpoint: Option<u64>,
    /// Unix timestamp in milliseconds of the beginning of the epoch.
    pub start_ms: Option<u64>,
    /// Unix timestamp in milliseconds of the end of the epoch.
    pub end_ms: Option<u64>,
    /// Reference gas price denominated in NANOS.
    pub reference_gas_price: Option<u64>,
    /// The protocol config of the epoch.
    pub protocol_config: Option<GrpcProtocolConfig>,
}

impl TryFrom<&proto::epoch::Epoch> for EpochInfo {
    type Error = SdkFfiError;

    fn try_from(value: &proto::epoch::Epoch) -> Result<Self> {
        Ok(Self {
            epoch: value.epoch,
            committee: value
                .committee
                .as_ref()
                .map(|_| value.committee().map_err(SdkFfiError::new))
                .transpose()?
                .map(|committee| Arc::new(committee.into())),
            system_state_bcs: value.bcs_system_state.as_ref().map(Vec::from),
            first_checkpoint: value.first_checkpoint,
            last_checkpoint: value.last_checkpoint,
            start_ms: value.start.map(proto_to_timestamp_ms).transpose()?,
            end_ms: value.end.map(proto_to_timestamp_ms).transpose()?,
            reference_gas_price: value.reference_gas_price,
            protocol_config: value.protocol_config.as_ref().map(Into::into),
        })
    }
}

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
            .get_epoch(
                epoch,
                crate::grpc::api::read_mask::<EpochReadMask>(&read_mask),
            )
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
