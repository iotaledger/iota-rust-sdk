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
    graphql::output_types::{
        DryRunEffect, DryRunMutation, DryRunResult, DryRunReturn, TransactionArgument,
    },
    types::{
        checkpoint::{CheckpointContents, CheckpointSummary},
        coin::Coin,
        digest::Digest,
        events::{Event, TransactionEvents},
        execution_status::ExecutionError,
        move_core::TypeTag,
        object::{Object, ObjectId},
        signature::UserSignature,
        transaction::{Argument, Transaction, TransactionEffects},
        validator::{ValidatorAggregatedSignature, ValidatorCommittee},
        version::Version,
    },
};

/// A reference to an object to fetch with `get_objects`, with an optional
/// version. If no version is provided, the latest version is returned.
#[derive(uniffi::Record)]
pub struct ObjectRequest {
    /// The id of the object.
    pub object_id: Arc<ObjectId>,
    /// The optional version of the object.
    #[uniffi(default = None)]
    pub version: Option<Arc<Version>>,
}

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
    pub checkpoint_height: Option<u64>,
    /// Unix timestamp in milliseconds of the most recently executed
    /// checkpoint.
    pub checkpoint_timestamp_ms: Option<u64>,
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
            checkpoint_height: value.executed_checkpoint_height,
            checkpoint_timestamp_ms: value
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
    pub committee: Option<ValidatorCommittee>,
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
                .map(Into::into),
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

/// A transaction that has been executed, along with its signatures, effects,
/// events and objects.
///
/// The `transaction`, `effects`, `events`, and input/output object fields are
/// deserialized from BCS, so the read mask must include the corresponding
/// `bcs` sub-fields for them to be populated; digest-only read masks populate
/// only the digest fields.
#[derive(uniffi::Record)]
pub struct ExecutedTransaction {
    /// The digest of the transaction.
    pub digest: Option<Arc<Digest>>,
    /// The transaction itself.
    pub transaction: Option<Arc<Transaction>>,
    /// The user signatures that authorized the execution of the transaction.
    pub signatures: Option<Vec<Arc<UserSignature>>>,
    /// The digest of the transaction effects.
    pub effects_digest: Option<Arc<Digest>>,
    /// The effects of the transaction.
    pub effects: Option<Arc<TransactionEffects>>,
    /// The digest of the transaction events.
    pub events_digest: Option<Arc<Digest>>,
    /// The events emitted by the transaction, if any.
    pub events: Option<Arc<TransactionEvents>>,
    /// The sequence number of the checkpoint that includes the transaction.
    pub checkpoint: Option<u64>,
    /// Unix timestamp in milliseconds of the checkpoint that includes the
    /// transaction.
    pub timestamp_ms: Option<u64>,
    /// The input objects used by the transaction.
    pub input_objects: Option<Vec<Arc<Object>>>,
    /// The output objects produced by the transaction.
    pub output_objects: Option<Vec<Arc<Object>>>,
}

impl TryFrom<&proto::transaction::ExecutedTransaction> for ExecutedTransaction {
    type Error = SdkFfiError;

    fn try_from(value: &proto::transaction::ExecutedTransaction) -> Result<Self> {
        Ok(Self {
            digest: value
                .transaction
                .as_ref()
                .and_then(|transaction| transaction.digest.as_ref())
                .map(iota_sdk::types::Digest::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            transaction: value
                .transaction
                .as_ref()
                .filter(|transaction| transaction.bcs.is_some())
                .map(|transaction| transaction.transaction().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            signatures: value
                .signatures
                .as_ref()
                .map(Vec::<iota_sdk::types::UserSignature>::try_from)
                .transpose()?
                .map(|signatures| {
                    signatures
                        .into_iter()
                        .map(Into::into)
                        .map(Arc::new)
                        .collect()
                }),
            effects_digest: value
                .effects
                .as_ref()
                .and_then(|effects| effects.digest.as_ref())
                .map(iota_sdk::types::Digest::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            effects: value
                .effects
                .as_ref()
                .filter(|effects| effects.bcs.is_some())
                .map(|effects| effects.effects().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            events_digest: value
                .events
                .as_ref()
                .and_then(|events| events.digest.as_ref())
                .map(iota_sdk::types::Digest::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            events: value
                .events
                .as_ref()
                .filter(|events| {
                    events
                        .events
                        .as_ref()
                        .is_some_and(|events| events.events.iter().all(|event| event.bcs.is_some()))
                })
                .map(|events| events.events().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            checkpoint: value.checkpoint,
            timestamp_ms: value.timestamp.map(proto_to_timestamp_ms).transpose()?,
            input_objects: value
                .input_objects
                .as_ref()
                .filter(|objects| objects.objects.iter().all(|object| object.bcs.is_some()))
                .map(Vec::<iota_sdk::types::Object>::try_from)
                .transpose()?
                .map(|objects| objects.into_iter().map(Into::into).map(Arc::new).collect()),
            output_objects: value
                .output_objects
                .as_ref()
                .filter(|objects| objects.objects.iter().all(|object| object.bcs.is_some()))
                .map(Vec::<iota_sdk::types::Object>::try_from)
                .transpose()?
                .map(|objects| objects.into_iter().map(Into::into).map(Arc::new).collect()),
        })
    }
}

/// The result of executing a single transaction in a batch: either the
/// executed transaction or an error.
#[derive(uniffi::Record)]
pub struct ExecutedTransactionResult {
    /// The executed transaction, if execution succeeded.
    pub transaction: Option<ExecutedTransaction>,
    /// The error message, if execution failed.
    pub error: Option<String>,
}

/// An intermediate result/output from the execution of a single command.
#[derive(uniffi::Record)]
pub struct CommandOutput {
    /// The argument the output corresponds to.
    pub argument: Option<Arc<Argument>>,
    /// The Move type of the output.
    pub type_tag: Option<Arc<TypeTag>>,
    /// The BCS representation of the output.
    pub bcs: Option<Vec<u8>>,
    /// The JSON rendering of the output.
    pub json: Option<serde_json::Value>,
}

impl TryFrom<&proto::command::CommandOutput> for CommandOutput {
    type Error = SdkFfiError;

    fn try_from(value: &proto::command::CommandOutput) -> Result<Self> {
        Ok(Self {
            argument: value
                .argument
                .as_ref()
                .map(|argument| argument.argument().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            type_tag: value
                .type_tag
                .as_ref()
                .map(|type_tag| type_tag.type_tag().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            bcs: value.bcs.as_ref().map(Vec::from),
            json: value
                .json
                .is_some()
                .then(|| value.output_json().map_err(SdkFfiError::new))
                .transpose()?,
        })
    }
}

/// The intermediate results/outputs from the execution of a single command.
#[derive(uniffi::Record)]
pub struct CommandResult {
    /// The outputs of the arguments that were mutably borrowed by the command.
    pub mutated_by_ref: Vec<CommandOutput>,
    /// The return values of the command.
    pub return_values: Vec<CommandOutput>,
}

impl TryFrom<&proto::command::CommandResult> for CommandResult {
    type Error = SdkFfiError;

    fn try_from(value: &proto::command::CommandResult) -> Result<Self> {
        Ok(Self {
            mutated_by_ref: value
                .mutated_by_ref
                .as_ref()
                .map(|outputs| {
                    outputs
                        .outputs
                        .iter()
                        .map(TryInto::try_into)
                        .collect::<Result<Vec<_>>>()
                })
                .transpose()?
                .unwrap_or_default(),
            return_values: value
                .return_values
                .as_ref()
                .map(|outputs| {
                    outputs
                        .outputs
                        .iter()
                        .map(TryInto::try_into)
                        .collect::<Result<Vec<_>>>()
                })
                .transpose()?
                .unwrap_or_default(),
        })
    }
}

/// An error that occurred during the simulated execution of a transaction.
#[derive(uniffi::Record)]
pub struct SimulatedExecutionError {
    /// The kind of execution error.
    pub error: Option<ExecutionError>,
    /// The error source as a string.
    pub source: Option<String>,
    /// The index of the command that failed.
    pub command_index: Option<u64>,
}

impl TryFrom<&proto::transaction_execution_service::ExecutionError> for SimulatedExecutionError {
    type Error = SdkFfiError;

    fn try_from(value: &proto::transaction_execution_service::ExecutionError) -> Result<Self> {
        Ok(Self {
            error: value
                .bcs_kind
                .is_some()
                .then(|| value.error_kind().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into),
            source: value.source.clone(),
            command_index: value.command_index,
        })
    }
}

/// The result of simulating a transaction.
#[derive(uniffi::Record)]
pub struct SimulatedTransaction {
    /// The simulated executed transaction.
    pub transaction: Option<ExecutedTransaction>,
    /// The suggested gas price (in NANOS).
    pub suggested_gas_price: Option<u64>,
    /// The intermediate results/outputs for each command of the transaction,
    /// if the simulation succeeded.
    pub command_results: Option<Vec<CommandResult>>,
    /// The execution error, if the simulation failed.
    pub execution_error: Option<SimulatedExecutionError>,
}

impl TryFrom<&proto::transaction_execution_service::SimulatedTransaction> for SimulatedTransaction {
    type Error = SdkFfiError;

    fn try_from(
        value: &proto::transaction_execution_service::SimulatedTransaction,
    ) -> Result<Self> {
        Ok(Self {
            transaction: value
                .executed_transaction
                .as_ref()
                .map(TryInto::try_into)
                .transpose()?,
            suggested_gas_price: value.suggested_gas_price,
            command_results: value
                .command_results()
                .map(|results| {
                    results
                        .results
                        .iter()
                        .map(TryInto::try_into)
                        .collect::<Result<Vec<_>>>()
                })
                .transpose()?,
            execution_error: value.execution_error().map(TryInto::try_into).transpose()?,
        })
    }
}

/// The result of simulating a single transaction in a batch: either the
/// simulated transaction or an error.
#[derive(uniffi::Record)]
pub struct SimulatedTransactionResult {
    /// The simulated transaction, if the simulation succeeded.
    pub transaction: Option<SimulatedTransaction>,
    /// The error message, if the simulation failed.
    pub error: Option<String>,
}

/// A transaction to simulate with `simulate_transactions`.
#[derive(uniffi::Record)]
pub struct SimulateTransactionInput {
    /// The transaction to simulate.
    pub transaction: Arc<Transaction>,
    /// Whether to skip the VM checks during the simulation.
    #[uniffi(default = false)]
    pub skip_checks: bool,
}

/// Response for a checkpoint query.
///
/// Which fields are populated depends on the read mask used for the query;
/// the default read mask only includes the checkpoint summary.
///
/// The `summary`, `contents`, and `events` fields are deserialized from BCS,
/// so the read mask must include the corresponding `bcs` sub-fields for them
/// to be populated; digest-only read masks populate only the digest fields.
#[derive(uniffi::Record)]
pub struct CheckpointResponse {
    /// The checkpoint sequence number. Always available regardless of the
    /// read mask.
    pub sequence_number: u64,
    /// The digest of the checkpoint summary.
    pub summary_digest: Option<Arc<Digest>>,
    /// The checkpoint summary.
    pub summary: Option<Arc<CheckpointSummary>>,
    /// The aggregated validator signature of the checkpoint.
    pub signature: Option<Arc<ValidatorAggregatedSignature>>,
    /// The digest of the checkpoint contents.
    pub contents_digest: Option<Arc<Digest>>,
    /// The checkpoint contents.
    pub contents: Option<Arc<CheckpointContents>>,
    /// The transactions executed in the checkpoint.
    pub transactions: Vec<ExecutedTransaction>,
    /// The events emitted in the checkpoint. Only events whose BCS
    /// representation was requested are included.
    pub events: Vec<Event>,
}

impl TryFrom<&iota_sdk::grpc_client::CheckpointResponse> for CheckpointResponse {
    type Error = SdkFfiError;

    fn try_from(value: &iota_sdk::grpc_client::CheckpointResponse) -> Result<Self> {
        Ok(Self {
            sequence_number: value.sequence_number,
            summary_digest: value
                .summary
                .as_ref()
                .and_then(|summary| summary.digest.as_ref())
                .map(iota_sdk::types::Digest::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            summary: value
                .summary
                .as_ref()
                .filter(|summary| summary.bcs.is_some())
                .map(|summary| summary.summary().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            signature: value
                .signature
                .as_ref()
                .map(|signature| signature.signature().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            contents_digest: value
                .contents
                .as_ref()
                .and_then(|contents| contents.digest.as_ref())
                .map(iota_sdk::types::Digest::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            contents: value
                .contents
                .as_ref()
                .filter(|contents| contents.bcs.is_some())
                .map(|contents| contents.contents().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            transactions: value
                .executed_transactions
                .iter()
                .map(TryInto::try_into)
                .collect::<Result<_>>()?,
            events: value
                .events
                .iter()
                .filter(|event| event.bcs.is_some())
                .map(|event| event.event().map_err(SdkFfiError::new))
                .collect::<std::result::Result<Vec<_>, _>>()?
                .into_iter()
                .map(Into::into)
                .collect(),
        })
    }
}

/// The state of the `MetadataCap` of a coin type.
#[derive(uniffi::Enum)]
pub enum MetadataCapState {
    /// The state of the `MetadataCap` is unknown.
    Unknown,
    /// The `MetadataCap` has been claimed.
    Claimed,
    /// The `MetadataCap` has not been claimed.
    Unclaimed,
    /// The `MetadataCap` has been deleted.
    Deleted,
}

impl From<proto::coin::coin_metadata::MetadataCapState> for MetadataCapState {
    fn from(value: proto::coin::coin_metadata::MetadataCapState) -> Self {
        match value {
            proto::coin::coin_metadata::MetadataCapState::Claimed => Self::Claimed,
            proto::coin::coin_metadata::MetadataCapState::Unclaimed => Self::Unclaimed,
            proto::coin::coin_metadata::MetadataCapState::Deleted => Self::Deleted,
            _ => Self::Unknown,
        }
    }
}

/// The metadata of a coin type.
#[derive(uniffi::Record)]
pub struct GrpcCoinMetadata {
    /// The id of the `0x2::coin::CoinMetadata` object or
    /// `Currency` object (when registered with the `CoinRegistry`).
    pub id: Option<Arc<ObjectId>>,
    /// Number of decimal places the coin uses.
    pub decimals: Option<u32>,
    /// Name for the token.
    pub name: Option<String>,
    /// Symbol for the token.
    pub symbol: Option<String>,
    /// Description of the token.
    pub description: Option<String>,
    /// URL for the token logo.
    pub icon_url: Option<String>,
    /// The `MetadataCap` id if it has been claimed for the coin type.
    pub metadata_cap_id: Option<Arc<ObjectId>>,
    /// State of the `MetadataCap` for the coin type.
    pub metadata_cap_state: Option<MetadataCapState>,
}

impl TryFrom<&proto::coin::CoinMetadata> for GrpcCoinMetadata {
    type Error = SdkFfiError;

    fn try_from(value: &proto::coin::CoinMetadata) -> Result<Self> {
        Ok(Self {
            id: value
                .id
                .as_ref()
                .map(iota_sdk::types::ObjectId::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            decimals: value.decimals,
            name: value.name.clone(),
            symbol: value.symbol.clone(),
            description: value.description.clone(),
            icon_url: value.icon_url.clone(),
            metadata_cap_id: value
                .metadata_cap_id
                .as_ref()
                .map(iota_sdk::types::ObjectId::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            metadata_cap_state: value
                .metadata_cap_state
                .and_then(|state| {
                    proto::coin::coin_metadata::MetadataCapState::try_from(state).ok()
                })
                .map(Into::into),
        })
    }
}

/// The supply state of a coin type.
#[derive(uniffi::Enum)]
pub enum SupplyState {
    /// The supply is unknown or the `TreasuryCap` still exists (minting still
    /// possible).
    Unknown,
    /// The supply is fixed (the `TreasuryCap` was consumed, no more minting
    /// possible).
    Fixed,
    /// The supply can only be burned.
    BurnOnly,
}

impl From<proto::coin::coin_treasury::SupplyState> for SupplyState {
    fn from(value: proto::coin::coin_treasury::SupplyState) -> Self {
        match value {
            proto::coin::coin_treasury::SupplyState::Fixed => Self::Fixed,
            proto::coin::coin_treasury::SupplyState::BurnOnly => Self::BurnOnly,
            _ => Self::Unknown,
        }
    }
}

/// The treasury of a coin type.
#[derive(uniffi::Record)]
pub struct GrpcCoinTreasury {
    /// The id of the `0x2::coin::TreasuryCap` object.
    pub id: Option<Arc<ObjectId>>,
    /// Total available supply for the coin type.
    pub total_supply: Option<u64>,
    /// Supply state indicating if the supply is fixed or can still be minted.
    pub supply_state: Option<SupplyState>,
}

impl TryFrom<&proto::coin::CoinTreasury> for GrpcCoinTreasury {
    type Error = SdkFfiError;

    fn try_from(value: &proto::coin::CoinTreasury) -> Result<Self> {
        Ok(Self {
            id: value
                .id
                .as_ref()
                .map(iota_sdk::types::ObjectId::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            total_supply: value.total_supply,
            supply_state: value
                .supply_state
                .and_then(|state| proto::coin::coin_treasury::SupplyState::try_from(state).ok())
                .map(Into::into),
        })
    }
}

/// The regulated state of a coin type.
#[derive(uniffi::Enum)]
pub enum CoinRegulatedState {
    /// The regulated state of the coin is unknown.
    Unknown,
    /// The coin is regulated.
    Regulated,
    /// The coin is not regulated.
    Unregulated,
}

impl From<proto::coin::regulated_coin_metadata::CoinRegulatedState> for CoinRegulatedState {
    fn from(value: proto::coin::regulated_coin_metadata::CoinRegulatedState) -> Self {
        match value {
            proto::coin::regulated_coin_metadata::CoinRegulatedState::Regulated => Self::Regulated,
            proto::coin::regulated_coin_metadata::CoinRegulatedState::Unregulated => {
                Self::Unregulated
            }
            _ => Self::Unknown,
        }
    }
}

/// The regulated metadata of a coin type.
#[derive(uniffi::Record)]
pub struct GrpcRegulatedCoinMetadata {
    /// The id of the `0x2::coin::RegulatedCoinMetadata` object.
    pub id: Option<Arc<ObjectId>>,
    /// The id of the coin's `CoinMetadata` or `CoinData` object.
    pub coin_metadata_object: Option<Arc<ObjectId>>,
    /// The id of the coin's `DenyCap` object.
    pub deny_cap_object: Option<Arc<ObjectId>>,
    /// Whether the coin can be globally paused.
    pub allow_global_pause: Option<bool>,
    /// Variant of the regulated coin metadata.
    pub variant: Option<u32>,
    /// The coin's regulated state.
    pub coin_regulated_state: Option<CoinRegulatedState>,
}

impl TryFrom<&proto::coin::RegulatedCoinMetadata> for GrpcRegulatedCoinMetadata {
    type Error = SdkFfiError;

    fn try_from(value: &proto::coin::RegulatedCoinMetadata) -> Result<Self> {
        Ok(Self {
            id: value
                .id
                .as_ref()
                .map(iota_sdk::types::ObjectId::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            coin_metadata_object: value
                .coin_metadata_object
                .as_ref()
                .map(iota_sdk::types::ObjectId::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            deny_cap_object: value
                .deny_cap_object
                .as_ref()
                .map(iota_sdk::types::ObjectId::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            allow_global_pause: value.allow_global_pause,
            variant: value.variant,
            coin_regulated_state: value
                .coin_regulated_state
                .and_then(|state| {
                    proto::coin::regulated_coin_metadata::CoinRegulatedState::try_from(state).ok()
                })
                .map(Into::into),
        })
    }
}

/// Information about a coin type.
#[derive(uniffi::Record)]
pub struct GrpcCoinInfo {
    /// The coin type.
    pub coin_type: Option<String>,
    /// Information about the coin type's `0x2::coin::CoinMetadata`, if it
    /// exists and has not been wrapped.
    pub metadata: Option<GrpcCoinMetadata>,
    /// Information about the coin type's `0x2::coin::TreasuryCap`, if it
    /// exists and has not been wrapped.
    pub treasury: Option<GrpcCoinTreasury>,
    /// Information about the coin type's regulated metadata, if the coin is
    /// regulated.
    pub regulated_metadata: Option<GrpcRegulatedCoinMetadata>,
}

impl TryFrom<&proto::state_service::GetCoinInfoResponse> for GrpcCoinInfo {
    type Error = SdkFfiError;

    fn try_from(value: &proto::state_service::GetCoinInfoResponse) -> Result<Self> {
        Ok(Self {
            coin_type: value.coin_type.clone(),
            metadata: value.metadata.as_ref().map(TryInto::try_into).transpose()?,
            treasury: value.treasury.as_ref().map(TryInto::try_into).transpose()?,
            regulated_metadata: value
                .regulated_metadata
                .as_ref()
                .map(TryInto::try_into)
                .transpose()?,
        })
    }
}

/// The kind of a dynamic field.
#[derive(uniffi::Enum)]
pub enum DynamicFieldKind {
    /// The kind of the dynamic field is unknown.
    Unknown,
    /// A dynamic field.
    Field,
    /// A dynamic object field.
    Object,
}

impl From<proto::dynamic_field::dynamic_field::DynamicFieldKind> for DynamicFieldKind {
    fn from(value: proto::dynamic_field::dynamic_field::DynamicFieldKind) -> Self {
        match value {
            proto::dynamic_field::dynamic_field::DynamicFieldKind::Field => Self::Field,
            proto::dynamic_field::dynamic_field::DynamicFieldKind::Object => Self::Object,
            _ => Self::Unknown,
        }
    }
}

/// A dynamic field of an object.
#[derive(uniffi::Record)]
pub struct DynamicField {
    /// The kind of the dynamic field.
    pub kind: Option<DynamicFieldKind>,
    /// The id of the dynamic field's parent object.
    pub parent: Option<Arc<ObjectId>>,
    /// The id of the dynamic field object.
    pub field_id: Option<Arc<ObjectId>>,
    /// The dynamic field object itself.
    pub field_object: Option<Arc<Object>>,
    /// The BCS representation of the dynamic field's name.
    pub name_bcs: Option<Vec<u8>>,
    /// The BCS representation of the dynamic field's value.
    ///
    /// For regular dynamic fields this contains the BCS-encoded value whose
    /// type is given by `value_type`. For dynamic *object* fields this
    /// contains the BCS-encoded id of the child object; use `child_object`
    /// to access the full object.
    pub value_bcs: Option<Vec<u8>>,
    /// The type of the dynamic field's value.
    pub value_type: Option<String>,
    /// The id of the child object when a child is a dynamic object field.
    pub child_id: Option<Arc<ObjectId>>,
    /// The object itself when a child is a dynamic object field.
    pub child_object: Option<Arc<Object>>,
}

impl TryFrom<&proto::dynamic_field::DynamicField> for DynamicField {
    type Error = SdkFfiError;

    fn try_from(value: &proto::dynamic_field::DynamicField) -> Result<Self> {
        Ok(Self {
            kind: value
                .kind
                .and_then(|kind| {
                    proto::dynamic_field::dynamic_field::DynamicFieldKind::try_from(kind).ok()
                })
                .map(Into::into),
            parent: value
                .parent
                .as_ref()
                .map(iota_sdk::types::ObjectId::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            field_id: value
                .field_id
                .as_ref()
                .map(iota_sdk::types::ObjectId::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            field_object: value
                .field_object
                .as_ref()
                .filter(|object| object.bcs.is_some())
                .map(|object| object.object().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            name_bcs: value.name.as_ref().map(Vec::from),
            value_bcs: value.value.as_ref().map(Vec::from),
            value_type: value.value_type.clone(),
            child_id: value
                .child_id
                .as_ref()
                .map(iota_sdk::types::ObjectId::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            child_object: value
                .child_object
                .as_ref()
                .filter(|object| object.bcs.is_some())
                .map(|object| object.object().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
        })
    }
}

/// A version of a Move package.
#[derive(uniffi::Record)]
pub struct PackageVersion {
    /// The original (immutable) package id shared across all versions.
    pub original_id: Option<Arc<ObjectId>>,
    /// The storage id of the specific package version.
    pub storage_id: Option<Arc<ObjectId>>,
    /// The version number.
    pub version: Option<u64>,
}

impl TryFrom<&proto::move_package_service::PackageVersion> for PackageVersion {
    type Error = SdkFfiError;

    fn try_from(value: &proto::move_package_service::PackageVersion) -> Result<Self> {
        Ok(Self {
            original_id: value
                .original_id
                .as_ref()
                .map(iota_sdk::types::ObjectId::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            storage_id: value
                .storage_id
                .as_ref()
                .map(iota_sdk::types::ObjectId::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            version: value.version,
        })
    }
}

/// A page of objects returned by the gRPC server.
#[derive(uniffi::Record)]
pub struct OwnedObjectPage {
    /// The objects returned in the page.
    pub objects: Vec<Arc<Object>>,
    /// Token to retrieve the next page. `None` when this is the last page.
    pub next_page_token: Option<Vec<u8>>,
}

/// A page of coins returned by the gRPC server.
#[derive(uniffi::Record)]
pub struct GrpcCoinPage {
    /// The coins returned in the page.
    pub coins: Vec<Arc<Coin>>,
    /// Token to retrieve the next page. `None` when this is the last page.
    pub next_page_token: Option<Vec<u8>>,
}

/// A page of dynamic fields returned by the gRPC server.
#[derive(uniffi::Record)]
pub struct DynamicFieldPage {
    /// The dynamic fields returned in the page.
    pub dynamic_fields: Vec<DynamicField>,
    /// Token to retrieve the next page. `None` when this is the last page.
    pub next_page_token: Option<Vec<u8>>,
}

/// A page of package versions returned by the gRPC server.
#[derive(uniffi::Record)]
pub struct PackageVersionPage {
    /// The package versions returned in the page.
    pub versions: Vec<PackageVersion>,
    /// Token to retrieve the next page. `None` when this is the last page.
    pub next_page_token: Option<Vec<u8>>,
}

/// Convert a simulated transaction returned by the gRPC client into the
/// common [`DryRunResult`] shape used by the transaction builder.
pub(crate) fn dry_run_result_from_simulated(
    value: &proto::transaction_execution_service::SimulatedTransaction,
) -> Result<DryRunResult> {
    let error = value.execution_error().map(|error| {
        error.source.clone().unwrap_or_else(|| {
            error
                .error_kind()
                .map(|kind| kind.to_string())
                .unwrap_or_else(|_| "execution error".to_string())
        })
    });
    let results = value
        .command_results()
        .map(|results| {
            results
                .results
                .iter()
                .map(dry_run_effect)
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();
    let executed = value.executed_transaction.as_ref();
    let transaction = executed
        .and_then(|tx| tx.transaction.as_ref())
        .filter(|transaction| transaction.bcs.is_some())
        .map(|transaction| transaction.transaction().map_err(SdkFfiError::new))
        .transpose()?
        .map(|transaction| {
            let signatures = executed
                .and_then(|tx| tx.signatures.as_ref())
                .map(Vec::<iota_sdk::types::UserSignature>::try_from)
                .transpose()?
                .unwrap_or_default();
            Ok::<_, SdkFfiError>(
                iota_sdk::types::SignedTransaction {
                    transaction,
                    signatures,
                }
                .into(),
            )
        })
        .transpose()?;
    let effects = executed
        .and_then(|tx| tx.effects.as_ref())
        .filter(|effects| effects.bcs.is_some())
        .map(|effects| effects.effects().map_err(SdkFfiError::new))
        .transpose()?
        .map(Into::into)
        .map(Arc::new);

    Ok(DryRunResult {
        error,
        results,
        transaction,
        effects,
    })
}

fn dry_run_effect(value: &proto::command::CommandResult) -> Result<DryRunEffect> {
    Ok(DryRunEffect {
        mutated_references: value
            .mutated_by_ref
            .as_ref()
            .map(|outputs| {
                outputs
                    .outputs
                    .iter()
                    .map(dry_run_mutation)
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default(),
        return_values: value
            .return_values
            .as_ref()
            .map(|outputs| {
                outputs
                    .outputs
                    .iter()
                    .map(dry_run_return)
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default(),
    })
}

fn dry_run_mutation(value: &proto::command::CommandOutput) -> Result<DryRunMutation> {
    Ok(DryRunMutation {
        input: transaction_argument(value.argument()?),
        type_tag: Arc::new(value.type_tag()?.into()),
        bcs: value.output_bcs()?.to_vec(),
    })
}

fn dry_run_return(value: &proto::command::CommandOutput) -> Result<DryRunReturn> {
    Ok(DryRunReturn {
        type_tag: Arc::new(value.type_tag()?.into()),
        bcs: value.output_bcs()?.to_vec(),
    })
}

fn transaction_argument(value: iota_sdk::types::Argument) -> TransactionArgument {
    match value {
        iota_sdk::types::Argument::Gas => TransactionArgument::GasCoin,
        iota_sdk::types::Argument::Input(index) => TransactionArgument::Input {
            index: index.into(),
        },
        iota_sdk::types::Argument::Result(cmd) => TransactionArgument::Result {
            cmd: cmd.into(),
            index: None,
        },
        iota_sdk::types::Argument::NestedResult(cmd, index) => TransactionArgument::Result {
            cmd: cmd.into(),
            index: Some(index.into()),
        },
        _ => unimplemented!("a new enum variant was added and needs to be handled"),
    }
}
