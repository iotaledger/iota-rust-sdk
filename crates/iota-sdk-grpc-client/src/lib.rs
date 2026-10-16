// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![cfg_attr(doc_cfg, feature(doc_cfg))]

mod api;
mod transaction_builder_client;

// Re-export all read mask constants (per-method fields)
#[cfg(feature = "move-types")]
pub use api::state::move_objects::{ListOwnedMoveObjectsQuery, OwnedMoveObject};
pub use api::{
    // CheckpointResponse per-method masks
    CHECKPOINT_CONTENTS_BCS,
    CHECKPOINT_CONTENTS_DIGEST,
    CHECKPOINT_RESPONSE_CHECKPOINT_DATA,
    CHECKPOINT_RESPONSE_CONTENTS,
    CHECKPOINT_RESPONSE_EVENTS,
    CHECKPOINT_RESPONSE_EXECUTED_TRANSACTIONS,
    CHECKPOINT_RESPONSE_SIGNATURE,
    CHECKPOINT_RESPONSE_SIGNED_SUMMARY,
    CHECKPOINT_RESPONSE_SUMMARY,
    CHECKPOINT_SUMMARY_BCS,
    CHECKPOINT_SUMMARY_DIGEST,
    // Event per-method masks
    EVENT_BCS,
    EVENT_BCS_CONTENTS,
    EVENT_JSON_CONTENTS,
    EVENT_MODULE,
    EVENT_PACKAGE_ID,
    EVENT_SENDER,
    EVENT_TYPE,
    // ExecutedTransaction per-method masks
    EXECUTED_TRANSACTION_CHECKPOINT,
    EXECUTED_TRANSACTION_EFFECTS,
    EXECUTED_TRANSACTION_EVENTS,
    EXECUTED_TRANSACTION_INPUT_OBJECTS,
    EXECUTED_TRANSACTION_OUTPUT_OBJECTS,
    EXECUTED_TRANSACTION_SIGNATURES,
    EXECUTED_TRANSACTION_TIMESTAMP,
    EXECUTED_TRANSACTION_TRANSACTION,
    // ExecutionError sub-fields
    EXECUTION_ERROR_BCS_KIND,
    EXECUTION_ERROR_COMMAND_INDEX,
    EXECUTION_ERROR_SOURCE,
    // Object per-method masks
    OBJECT_BCS,
    OBJECT_REFERENCE,
    // SimulatedTransaction per-method masks
    SIMULATED_TRANSACTION_EXECUTED_TRANSACTION,
    SIMULATED_TRANSACTION_EXECUTION_RESULT,
    SIMULATED_TRANSACTION_SUGGESTED_GAS_PRICE,
    // Transaction / Effects / Events sub-fields
    TRANSACTION_BCS,
    TRANSACTION_DIGEST,
    TRANSACTION_EFFECTS_BCS,
    TRANSACTION_EFFECTS_DIGEST,
    TRANSACTION_EVENTS_BCS,
    TRANSACTION_EVENTS_DIGEST,
    // ViewFunctionCall per-method masks
    VIEW_FUNCTION_CALL_OUTPUTS_EXECUTION_RESULT,
};
// Re-export types for convenience
pub use api::{
    CheckpointResponse, CheckpointStreamError, CheckpointStreamItem, GrpcError, GrpcResult,
    MetadataEnvelope, Page, ProtocolError, RpcStatus,
    execution::simulate::SimulateTransactionInput,
};
// Re-export all read mask constants (endpoint defaults)
pub use api::{
    // Endpoint defaults
    EXECUTE_TRANSACTIONS_READ_MASK,
    GET_CHECKPOINT_READ_MASK,
    GET_EPOCH_READ_MASK,
    GET_OBJECTS_READ_MASK,
    GET_SERVICE_INFO_READ_MASK,
    GET_TRANSACTIONS_READ_MASK,
    LIST_DYNAMIC_FIELDS_READ_MASK,
    LIST_OWNED_OBJECTS_READ_MASK,
    SIMULATE_TRANSACTIONS_READ_MASK,
    VIEW_FUNCTION_CALLS_READ_MASK,
};
// Re-export query builders for convenience
pub use api::{
    execution::{
        execute::{ExecuteTransactionQuery, ExecuteTransactionsQuery},
        simulate::{SimulateTransactionQuery, SimulateTransactionsQuery},
        view::{ViewFunctionCallQuery, ViewFunctionCallsQuery},
    },
    ledger::{
        checkpoints::{CheckpointsStreamFilteredQuery, CheckpointsStreamQuery, GetCheckpointQuery},
        epochs::{GetEpochQuery, GetReferenceGasPriceQuery},
        health::GetHealthQuery,
        objects::{GetObjectReferencesQuery, GetObjectsQuery},
        service_info::GetServiceInfoQuery,
        transactions::GetTransactionsQuery,
    },
    move_package::package_versions::ListPackageVersionsQuery,
    state::{
        coin_info::GetCoinInfoQuery, coins::GetCoinsQuery, dynamic_fields::ListDynamicFieldsQuery,
        owned_objects::ListOwnedObjectsQuery,
    },
};
// Re-export typed read mask field enums
pub use iota_grpc_types::read_mask_fields;
pub use iota_grpc_types::{prost, prost_types, tonic};
pub use iota_types;

mod client;
pub use client::{GrpcClient, InterceptedChannel};

mod response_ext;
pub use response_ext::ResponseExt;

mod interceptors;
pub use interceptors::HeadersInterceptor;
