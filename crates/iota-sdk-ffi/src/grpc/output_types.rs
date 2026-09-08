// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Output types for the gRPC client methods.
//!
//! The gRPC API lets callers control which fields the server returns via read
//! masks. Fields that were not requested (or that the server did not populate)
//! are `None` in the corresponding record.
//!
//! Complex types (transactions, effects, events, objects, ...) are eagerly
//! deserialized from their BCS representation, so the read mask must include
//! the corresponding `bcs` sub-fields for those record fields to be
//! populated.

use std::{collections::HashMap, sync::Arc};

use iota_sdk::grpc_types::{proto::proto_to_timestamp_ms, v1 as proto};

use crate::{
    error::{Result, SdkFfiError},
    types::{digest::Digest, validator::ValidatorCommittee},
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
