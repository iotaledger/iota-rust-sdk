// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Read mask field path constants for gRPC endpoints.
//!
//! Each endpoint has a dedicated namespace struct whose associated `&str`
//! constants represent the fields that the server can return. Pass one or
//! more constants to `ReadMask::from` (single field) or
//! `ReadMask::from` with a `&[&str]` slice (multiple fields) in the
//! `iota-sdk-grpc-client` crate.
//!
//! # Example
//!
//! ```
//! use iota_sdk_grpc_types::read_mask_fields::TransactionField;
//!
//! assert_eq!(TransactionField::EFFECTS, "effects");
//! assert_eq!(TransactionField::EFFECTS_BCS, "effects.bcs");
//! assert_eq!(TransactionField::CHECKPOINT, "checkpoint");
//! ```

// =============================================================================
// get_objects
// =============================================================================

/// Field paths for `get_objects`.
pub struct ObjectField;

impl ObjectField {
    /// Wildcard — request all object fields.
    pub const ALL: &str = "*";
    /// Object reference (object_id, version, digest).
    pub const REFERENCE: &str = "reference";
    /// The object ID.
    pub const REFERENCE_OBJECT_ID: &str = "reference.object_id";
    /// The object version.
    pub const REFERENCE_VERSION: &str = "reference.version";
    /// The object content digest.
    pub const REFERENCE_DIGEST: &str = "reference.digest";
    /// The full BCS-encoded object.
    pub const BCS: &str = "bcs";
}

// =============================================================================
// list_owned_objects
// =============================================================================

/// Field paths for `list_owned_objects`.
pub struct OwnedObjectField;

impl OwnedObjectField {
    /// Wildcard — request all fields.
    pub const ALL: &str = "*";
    /// Object reference (object_id, version, digest).
    pub const REFERENCE: &str = "reference";
    /// The object ID.
    pub const REFERENCE_OBJECT_ID: &str = "reference.object_id";
    /// The object version.
    pub const REFERENCE_VERSION: &str = "reference.version";
    /// The object content digest.
    pub const REFERENCE_DIGEST: &str = "reference.digest";
    /// The Move type of the object.
    pub const OBJECT_TYPE: &str = "object_type";
    /// The object owner.
    pub const OWNER: &str = "owner";
    /// The full BCS-encoded object.
    pub const BCS: &str = "bcs";
}

// =============================================================================
// get_transactions / execute_transaction (unprefixed paths)
// =============================================================================

/// Field paths for `get_transactions` / `execute_transaction`.
pub struct TransactionField;

impl TransactionField {
    /// Wildcard — request all fields.
    pub const ALL: &str = "*";
    /// Transaction data (all sub-fields).
    pub const TRANSACTION: &str = "transaction";
    /// The transaction digest.
    pub const TRANSACTION_DIGEST: &str = "transaction.digest";
    /// The full BCS-encoded transaction.
    pub const TRANSACTION_BCS: &str = "transaction.bcs";
    /// User signatures (all sub-fields).
    pub const SIGNATURES: &str = "signatures";
    /// The full BCS-encoded signatures.
    pub const SIGNATURES_BCS: &str = "signatures.bcs";
    /// Transaction effects (all sub-fields).
    pub const EFFECTS: &str = "effects";
    /// The effects digest.
    pub const EFFECTS_DIGEST: &str = "effects.digest";
    /// The full BCS-encoded effects.
    pub const EFFECTS_BCS: &str = "effects.bcs";
    /// Transaction events (all sub-fields).
    pub const EVENTS: &str = "events";
    /// The events digest.
    pub const EVENTS_DIGEST: &str = "events.digest";
    /// Individual events (all sub-fields).
    pub const EVENTS_EVENTS: &str = "events.events";
    /// Full BCS-encoded event.
    pub const EVENTS_EVENTS_BCS: &str = "events.events.bcs";
    /// The ID of the package that emitted the event.
    pub const EVENTS_EVENTS_PACKAGE_ID: &str = "events.events.package_id";
    /// The module that emitted the event.
    pub const EVENTS_EVENTS_MODULE: &str = "events.events.module";
    /// The sender that triggered the event.
    pub const EVENTS_EVENTS_SENDER: &str = "events.events.sender";
    /// The type of the event.
    pub const EVENTS_EVENTS_EVENT_TYPE: &str = "events.events.event_type";
    /// The full BCS-encoded contents of the event.
    pub const EVENTS_EVENTS_BCS_CONTENTS: &str = "events.events.bcs_contents";
    /// The JSON-encoded contents of the event.
    pub const EVENTS_EVENTS_JSON_CONTENTS: &str = "events.events.json_contents";
    /// Checkpoint sequence number that included the transaction.
    pub const CHECKPOINT: &str = "checkpoint";
    /// Timestamp of the checkpoint that included the transaction.
    pub const TIMESTAMP: &str = "timestamp";
    /// Input objects (all sub-fields).
    pub const INPUT_OBJECTS: &str = "input_objects";
    /// Input object reference (object_id, version, digest).
    pub const INPUT_OBJECTS_REFERENCE: &str = "input_objects.reference";
    /// Input object ID.
    pub const INPUT_OBJECTS_REFERENCE_OBJECT_ID: &str = "input_objects.reference.object_id";
    /// Input object version.
    pub const INPUT_OBJECTS_REFERENCE_VERSION: &str = "input_objects.reference.version";
    /// Input object digest.
    pub const INPUT_OBJECTS_REFERENCE_DIGEST: &str = "input_objects.reference.digest";
    /// The full BCS-encoded input object.
    pub const INPUT_OBJECTS_BCS: &str = "input_objects.bcs";
    /// Output objects (all sub-fields).
    pub const OUTPUT_OBJECTS: &str = "output_objects";
    /// Output object reference (object_id, version, digest).
    pub const OUTPUT_OBJECTS_REFERENCE: &str = "output_objects.reference";
    /// Output object ID.
    pub const OUTPUT_OBJECTS_REFERENCE_OBJECT_ID: &str = "output_objects.reference.object_id";
    /// Output object version.
    pub const OUTPUT_OBJECTS_REFERENCE_VERSION: &str = "output_objects.reference.version";
    /// Output object digest.
    pub const OUTPUT_OBJECTS_REFERENCE_DIGEST: &str = "output_objects.reference.digest";
    /// The full BCS-encoded output object.
    pub const OUTPUT_OBJECTS_BCS: &str = "output_objects.bcs";
    /// Balance changes (all sub-fields).
    pub const BALANCE_CHANGES: &str = "balance_changes";
    /// The owner whose balance changed.
    pub const BALANCE_CHANGES_OWNER: &str = "balance_changes.owner";
    /// The coin type of the balance change.
    pub const BALANCE_CHANGES_COIN_TYPE: &str = "balance_changes.coin_type";
    /// The signed amount of the balance change.
    pub const BALANCE_CHANGES_AMOUNT: &str = "balance_changes.amount";
    /// Object changes (all sub-fields).
    pub const OBJECT_CHANGES: &str = "object_changes";
    /// Published-package object changes.
    pub const OBJECT_CHANGES_PUBLISHED: &str = "object_changes.published";
    /// Mutated-object changes.
    pub const OBJECT_CHANGES_MUTATED: &str = "object_changes.mutated";
    /// Deleted-object changes.
    pub const OBJECT_CHANGES_DELETED: &str = "object_changes.deleted";
    /// Wrapped-object changes.
    pub const OBJECT_CHANGES_WRAPPED: &str = "object_changes.wrapped";
    /// Unwrapped-object changes.
    pub const OBJECT_CHANGES_UNWRAPPED: &str = "object_changes.unwrapped";
    /// Created-object changes.
    pub const OBJECT_CHANGES_CREATED: &str = "object_changes.created";
}

// =============================================================================
// Checkpoint transactions (prefixed with "transactions.")
// =============================================================================

/// Field paths for executed transactions within checkpoint responses.
///
/// All paths are prefixed with `transactions.`.
pub struct CheckpointTransactionField;

impl CheckpointTransactionField {
    /// All transaction fields within the checkpoint.
    pub const ALL: &str = "transactions";
    /// Transaction data (all sub-fields).
    pub const TRANSACTION: &str = "transactions.transaction";
    /// The transaction digest.
    pub const TRANSACTION_DIGEST: &str = "transactions.transaction.digest";
    /// The full BCS-encoded transaction.
    pub const TRANSACTION_BCS: &str = "transactions.transaction.bcs";
    /// User signatures (all sub-fields).
    pub const SIGNATURES: &str = "transactions.signatures";
    /// The full BCS-encoded signatures.
    pub const SIGNATURES_BCS: &str = "transactions.signatures.bcs";
    /// Transaction effects (all sub-fields).
    pub const EFFECTS: &str = "transactions.effects";
    /// The effects digest.
    pub const EFFECTS_DIGEST: &str = "transactions.effects.digest";
    /// The full BCS-encoded effects.
    pub const EFFECTS_BCS: &str = "transactions.effects.bcs";
    /// Transaction events (all sub-fields).
    pub const EVENTS: &str = "transactions.events";
    /// The events digest.
    pub const EVENTS_DIGEST: &str = "transactions.events.digest";
    /// Checkpoint sequence number.
    pub const CHECKPOINT: &str = "transactions.checkpoint";
    /// Timestamp.
    pub const TIMESTAMP: &str = "transactions.timestamp";
    /// Input objects (all sub-fields).
    pub const INPUT_OBJECTS: &str = "transactions.input_objects";
    /// The full BCS-encoded input object.
    pub const INPUT_OBJECTS_BCS: &str = "transactions.input_objects.bcs";
    /// Output objects (all sub-fields).
    pub const OUTPUT_OBJECTS: &str = "transactions.output_objects";
    /// The full BCS-encoded output object.
    pub const OUTPUT_OBJECTS_BCS: &str = "transactions.output_objects.bcs";
    /// Balance changes (all sub-fields).
    pub const BALANCE_CHANGES: &str = "transactions.balance_changes";
    /// Object changes (all sub-fields).
    pub const OBJECT_CHANGES: &str = "transactions.object_changes";
}

// =============================================================================
// Simulate executed transaction (prefixed with "executed_transaction.")
// =============================================================================

/// Field paths for the executed transaction within simulate responses.
///
/// All paths are prefixed with `executed_transaction.`.
pub struct SimulateExecutedTransactionField;

impl SimulateExecutedTransactionField {
    /// All executed transaction fields.
    pub const ALL: &str = "executed_transaction";
    /// Transaction data (all sub-fields).
    pub const TRANSACTION: &str = "executed_transaction.transaction";
    /// The transaction digest.
    pub const TRANSACTION_DIGEST: &str = "executed_transaction.transaction.digest";
    /// The full BCS-encoded transaction.
    pub const TRANSACTION_BCS: &str = "executed_transaction.transaction.bcs";
    /// User signatures (all sub-fields).
    pub const SIGNATURES: &str = "executed_transaction.signatures";
    /// The full BCS-encoded signatures.
    pub const SIGNATURES_BCS: &str = "executed_transaction.signatures.bcs";
    /// Transaction effects (all sub-fields).
    pub const EFFECTS: &str = "executed_transaction.effects";
    /// The effects digest.
    pub const EFFECTS_DIGEST: &str = "executed_transaction.effects.digest";
    /// The full BCS-encoded effects.
    pub const EFFECTS_BCS: &str = "executed_transaction.effects.bcs";
    /// Transaction events (all sub-fields).
    pub const EVENTS: &str = "executed_transaction.events";
    /// The events digest.
    pub const EVENTS_DIGEST: &str = "executed_transaction.events.digest";
    /// Individual events — full BCS-encoded.
    pub const EVENTS_EVENTS_BCS: &str = "executed_transaction.events.events.bcs";
    /// Checkpoint sequence number.
    pub const CHECKPOINT: &str = "executed_transaction.checkpoint";
    /// Timestamp.
    pub const TIMESTAMP: &str = "executed_transaction.timestamp";
    /// Input objects (all sub-fields).
    pub const INPUT_OBJECTS: &str = "executed_transaction.input_objects";
    /// The full BCS-encoded input object.
    pub const INPUT_OBJECTS_BCS: &str = "executed_transaction.input_objects.bcs";
    /// Output objects (all sub-fields).
    pub const OUTPUT_OBJECTS: &str = "executed_transaction.output_objects";
    /// The full BCS-encoded output object.
    pub const OUTPUT_OBJECTS_BCS: &str = "executed_transaction.output_objects.bcs";
    /// Balance changes (all sub-fields).
    pub const BALANCE_CHANGES: &str = "executed_transaction.balance_changes";
    /// Object changes (all sub-fields).
    pub const OBJECT_CHANGES: &str = "executed_transaction.object_changes";
}

// =============================================================================
// get_service_info
// =============================================================================

/// Field paths for `get_service_info`.
pub struct ServiceInfoField;

impl ServiceInfoField {
    /// Wildcard — request all fields.
    pub const ALL: &str = "*";
    /// The chain ID (network identifier).
    pub const CHAIN_ID: &str = "chain_id";
    /// The chain identifier string.
    pub const CHAIN: &str = "chain";
    /// The current epoch.
    pub const EPOCH: &str = "epoch";
    /// Height of the last executed checkpoint.
    pub const EXECUTED_CHECKPOINT_HEIGHT: &str = "executed_checkpoint_height";
    /// Timestamp of the last executed checkpoint.
    pub const EXECUTED_CHECKPOINT_TIMESTAMP: &str = "executed_checkpoint_timestamp";
    /// Lowest available checkpoint for transaction/checkpoint data.
    pub const LOWEST_AVAILABLE_CHECKPOINT: &str = "lowest_available_checkpoint";
    /// Lowest available checkpoint for object data.
    pub const LOWEST_AVAILABLE_CHECKPOINT_OBJECTS: &str = "lowest_available_checkpoint_objects";
    /// The server version.
    pub const SERVER: &str = "server";
}

// =============================================================================
// get_epoch
// =============================================================================

/// Field paths for `get_epoch`.
pub struct EpochField;

impl EpochField {
    /// Wildcard — request all fields.
    pub const ALL: &str = "*";
    /// The epoch number.
    pub const EPOCH: &str = "epoch";
    /// The validator committee for this epoch.
    pub const COMMITTEE: &str = "committee";
    /// The BCS-encoded system state.
    pub const BCS_SYSTEM_STATE: &str = "bcs_system_state";
    /// The first checkpoint in the epoch.
    pub const FIRST_CHECKPOINT: &str = "first_checkpoint";
    /// The last checkpoint in the epoch.
    pub const LAST_CHECKPOINT: &str = "last_checkpoint";
    /// The start timestamp of the epoch.
    pub const START: &str = "start";
    /// The end timestamp of the epoch.
    pub const END: &str = "end";
    /// The reference gas price during the epoch (in NANOS).
    pub const REFERENCE_GAS_PRICE: &str = "reference_gas_price";
    /// All protocol configuration fields.
    pub const PROTOCOL_CONFIG: &str = "protocol_config";
    /// The protocol version.
    pub const PROTOCOL_CONFIG_PROTOCOL_VERSION: &str = "protocol_config.protocol_version";
    /// All feature flags.
    pub const PROTOCOL_CONFIG_FEATURE_FLAGS: &str = "protocol_config.feature_flags";
    /// All protocol attributes.
    pub const PROTOCOL_CONFIG_ATTRIBUTES: &str = "protocol_config.attributes";
    /// All epoch-close-proof fields.
    pub const EPOCH_CLOSE_PROOF: &str = "epoch_close_proof";
    /// The certified checkpoint that closed the epoch.
    pub const EPOCH_CLOSE_PROOF_CHECKPOINT: &str = "epoch_close_proof.checkpoint";
    /// Effects of the epoch-change transaction.
    pub const EPOCH_CLOSE_PROOF_END_OF_EPOCH_TRANSACTION_EFFECTS: &str =
        "epoch_close_proof.end_of_epoch_transaction_effects";
    /// Events emitted by the epoch-change transaction.
    pub const EPOCH_CLOSE_PROOF_END_OF_EPOCH_TRANSACTION_EVENTS: &str =
        "epoch_close_proof.end_of_epoch_transaction_events";
    /// Raw BCS of the next epoch's start-of-epoch system-state objects.
    pub const EPOCH_CLOSE_PROOF_BCS_NEXT_EPOCH_SYSTEM_STATE_OBJECTS: &str =
        "epoch_close_proof.bcs_next_epoch_system_state_objects";

    /// Field path for a specific feature flag by key.
    ///
    /// # Example
    ///
    /// ```
    /// use iota_sdk_grpc_types::read_mask_fields::EpochField;
    ///
    /// assert_eq!(
    ///     EpochField::feature_flag("enable_vdf"),
    ///     "protocol_config.feature_flags.enable_vdf",
    /// );
    /// ```
    pub fn feature_flag(key: &str) -> String {
        format!("protocol_config.feature_flags.{key}")
    }

    /// Field path for a specific protocol attribute by key.
    ///
    /// # Example
    ///
    /// ```
    /// use iota_sdk_grpc_types::read_mask_fields::EpochField;
    ///
    /// assert_eq!(
    ///     EpochField::attribute("max_tx_gas"),
    ///     "protocol_config.attributes.max_tx_gas",
    /// );
    /// ```
    pub fn attribute(key: &str) -> String {
        format!("protocol_config.attributes.{key}")
    }
}

// =============================================================================
// Checkpoint responses (get_checkpoint_*, stream_checkpoints*)
// =============================================================================

/// Field paths for checkpoint responses.
pub struct CheckpointResponseField;

impl CheckpointResponseField {
    /// Wildcard — request all fields.
    pub const ALL: &str = "*";
    /// All checkpoint data fields.
    pub const CHECKPOINT: &str = "checkpoint";
    /// The checkpoint sequence number.
    pub const CHECKPOINT_SEQUENCE_NUMBER: &str = "checkpoint.sequence_number";
    /// Checkpoint summary (all sub-fields).
    pub const CHECKPOINT_SUMMARY: &str = "checkpoint.summary";
    /// The checkpoint summary digest.
    pub const CHECKPOINT_SUMMARY_DIGEST: &str = "checkpoint.summary.digest";
    /// The full BCS-encoded checkpoint summary.
    pub const CHECKPOINT_SUMMARY_BCS: &str = "checkpoint.summary.bcs";
    /// Checkpoint contents (all sub-fields).
    pub const CHECKPOINT_CONTENTS: &str = "checkpoint.contents";
    /// The checkpoint contents digest.
    pub const CHECKPOINT_CONTENTS_DIGEST: &str = "checkpoint.contents.digest";
    /// The full BCS-encoded checkpoint contents.
    pub const CHECKPOINT_CONTENTS_BCS: &str = "checkpoint.contents.bcs";
    /// The validator aggregated signature.
    pub const CHECKPOINT_SIGNATURE: &str = "checkpoint.signature";
    /// All transactions in the checkpoint.
    pub const TRANSACTIONS: &str = "transactions";
    /// All events in the checkpoint.
    pub const EVENTS: &str = "events";
}

/// Field paths for checkpoint-level events.
pub struct CheckpointEventField;

impl CheckpointEventField {
    /// All event fields.
    pub const ALL: &str = "events";
    /// Full BCS-encoded event.
    pub const BCS: &str = "events.bcs";
    /// The ID of the package that emitted the event.
    pub const PACKAGE_ID: &str = "events.package_id";
    /// The module that emitted the event.
    pub const MODULE: &str = "events.module";
    /// The sender that triggered the event.
    pub const SENDER: &str = "events.sender";
    /// The type of the event.
    pub const EVENT_TYPE: &str = "events.event_type";
    /// The full BCS-encoded contents of the event.
    pub const BCS_CONTENTS: &str = "events.bcs_contents";
    /// The JSON-encoded contents of the event.
    pub const JSON_CONTENTS: &str = "events.json_contents";
}

// =============================================================================
// simulate_transaction
// =============================================================================

/// Field paths for `simulate_transaction`.
pub struct SimulateField;

impl SimulateField {
    /// Wildcard — request all fields.
    pub const ALL: &str = "*";
    /// The simulated executed transaction (all sub-fields).
    pub const EXECUTED_TRANSACTION: &str = "executed_transaction";
    /// The suggested gas price (in NANOS).
    pub const SUGGESTED_GAS_PRICE: &str = "suggested_gas_price";
    /// Execution result (all sub-fields).
    pub const EXECUTION_RESULT: &str = "execution_result";
    /// Per-command results (on success, all sub-fields).
    pub const EXECUTION_RESULT_COMMAND_RESULTS: &str = "execution_result.command_results";
    /// Objects mutated by reference.
    pub const EXECUTION_RESULT_COMMAND_RESULTS_MUTATED_BY_REF: &str =
        "execution_result.command_results.mutated_by_ref";
    /// Return values from the command.
    pub const EXECUTION_RESULT_COMMAND_RESULTS_RETURN_VALUES: &str =
        "execution_result.command_results.return_values";
    /// Execution error details (on failure, all sub-fields).
    pub const EXECUTION_RESULT_EXECUTION_ERROR: &str = "execution_result.execution_error";
    /// The BCS-encoded error kind.
    pub const EXECUTION_RESULT_EXECUTION_ERROR_BCS_KIND: &str =
        "execution_result.execution_error.bcs_kind";
    /// The error source description.
    pub const EXECUTION_RESULT_EXECUTION_ERROR_SOURCE: &str =
        "execution_result.execution_error.source";
    /// The index of the command that failed.
    pub const EXECUTION_RESULT_EXECUTION_ERROR_COMMAND_INDEX: &str =
        "execution_result.execution_error.command_index";
}

// =============================================================================
// list_dynamic_fields
// =============================================================================

/// Field paths for `list_dynamic_fields`.
pub struct DynamicFieldField;

impl DynamicFieldField {
    /// Wildcard — request all fields.
    pub const ALL: &str = "*";
    /// The kind of dynamic field (field or object).
    pub const KIND: &str = "kind";
    /// The parent object ID.
    pub const PARENT: &str = "parent";
    /// The field object ID.
    pub const FIELD_ID: &str = "field_id";
    /// The child object ID (for dynamic object fields).
    pub const CHILD_ID: &str = "child_id";
    /// BCS-encoded field name.
    pub const NAME: &str = "name";
    /// BCS-encoded field value.
    pub const VALUE: &str = "value";
    /// The Move type of the value.
    pub const VALUE_TYPE: &str = "value_type";
    /// The full field object (sub-fields match `get_objects`).
    pub const FIELD_OBJECT: &str = "field_object";
    /// The full child object (sub-fields match `get_objects`).
    pub const CHILD_OBJECT: &str = "child_object";
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_field_paths() {
        assert_eq!(ObjectField::ALL, "*");
        assert_eq!(ObjectField::REFERENCE, "reference");
        assert_eq!(ObjectField::REFERENCE_OBJECT_ID, "reference.object_id");
        assert_eq!(ObjectField::BCS, "bcs");
    }

    #[test]
    fn transaction_field_paths() {
        assert_eq!(TransactionField::ALL, "*");
        assert_eq!(TransactionField::TRANSACTION_DIGEST, "transaction.digest");
        assert_eq!(TransactionField::EFFECTS_BCS, "effects.bcs");
        assert_eq!(TransactionField::EVENTS, "events");
        assert_eq!(TransactionField::EVENTS_EVENTS_BCS, "events.events.bcs");
        assert_eq!(TransactionField::CHECKPOINT, "checkpoint");
        assert_eq!(TransactionField::INPUT_OBJECTS_BCS, "input_objects.bcs");
        assert_eq!(TransactionField::OUTPUT_OBJECTS_BCS, "output_objects.bcs");
        assert_eq!(TransactionField::BALANCE_CHANGES, "balance_changes");
        assert_eq!(
            TransactionField::BALANCE_CHANGES_AMOUNT,
            "balance_changes.amount"
        );
        assert_eq!(TransactionField::OBJECT_CHANGES, "object_changes");
        assert_eq!(
            TransactionField::OBJECT_CHANGES_CREATED,
            "object_changes.created"
        );
    }

    #[test]
    fn checkpoint_transaction_field_paths() {
        assert_eq!(CheckpointTransactionField::ALL, "transactions");
        assert_eq!(
            CheckpointTransactionField::TRANSACTION_DIGEST,
            "transactions.transaction.digest"
        );
        assert_eq!(
            CheckpointTransactionField::EFFECTS_BCS,
            "transactions.effects.bcs"
        );
        assert_eq!(
            CheckpointTransactionField::BALANCE_CHANGES,
            "transactions.balance_changes"
        );
        assert_eq!(
            CheckpointTransactionField::OBJECT_CHANGES,
            "transactions.object_changes"
        );
    }

    #[test]
    fn simulate_executed_transaction_field_paths() {
        assert_eq!(
            SimulateExecutedTransactionField::ALL,
            "executed_transaction"
        );
        assert_eq!(
            SimulateExecutedTransactionField::EFFECTS,
            "executed_transaction.effects"
        );
        assert_eq!(
            SimulateExecutedTransactionField::EFFECTS_BCS,
            "executed_transaction.effects.bcs"
        );
        assert_eq!(
            SimulateExecutedTransactionField::BALANCE_CHANGES,
            "executed_transaction.balance_changes"
        );
        assert_eq!(
            SimulateExecutedTransactionField::OBJECT_CHANGES,
            "executed_transaction.object_changes"
        );
    }

    #[test]
    fn service_info_field_paths() {
        assert_eq!(ServiceInfoField::ALL, "*");
        assert_eq!(ServiceInfoField::CHAIN_ID, "chain_id");
        assert_eq!(ServiceInfoField::SERVER, "server");
    }

    #[test]
    fn epoch_field_paths() {
        assert_eq!(EpochField::ALL, "*");
        assert_eq!(EpochField::EPOCH, "epoch");
        assert_eq!(EpochField::REFERENCE_GAS_PRICE, "reference_gas_price");
        assert_eq!(
            EpochField::PROTOCOL_CONFIG_PROTOCOL_VERSION,
            "protocol_config.protocol_version"
        );
        assert_eq!(
            EpochField::PROTOCOL_CONFIG_FEATURE_FLAGS,
            "protocol_config.feature_flags"
        );
        assert_eq!(EpochField::EPOCH_CLOSE_PROOF, "epoch_close_proof");
        assert_eq!(
            EpochField::EPOCH_CLOSE_PROOF_CHECKPOINT,
            "epoch_close_proof.checkpoint"
        );
        assert_eq!(
            EpochField::EPOCH_CLOSE_PROOF_END_OF_EPOCH_TRANSACTION_EFFECTS,
            "epoch_close_proof.end_of_epoch_transaction_effects"
        );
        assert_eq!(
            EpochField::EPOCH_CLOSE_PROOF_END_OF_EPOCH_TRANSACTION_EVENTS,
            "epoch_close_proof.end_of_epoch_transaction_events"
        );
        assert_eq!(
            EpochField::EPOCH_CLOSE_PROOF_BCS_NEXT_EPOCH_SYSTEM_STATE_OBJECTS,
            "epoch_close_proof.bcs_next_epoch_system_state_objects"
        );
    }

    #[test]
    fn epoch_dynamic_paths() {
        assert_eq!(
            EpochField::feature_flag("enable_vdf"),
            "protocol_config.feature_flags.enable_vdf"
        );
        assert_eq!(
            EpochField::attribute("max_tx_gas"),
            "protocol_config.attributes.max_tx_gas"
        );
    }

    #[test]
    fn checkpoint_response_field_paths() {
        assert_eq!(CheckpointResponseField::ALL, "*");
        assert_eq!(CheckpointResponseField::CHECKPOINT, "checkpoint");
        assert_eq!(
            CheckpointResponseField::CHECKPOINT_SUMMARY_BCS,
            "checkpoint.summary.bcs"
        );
        assert_eq!(CheckpointResponseField::TRANSACTIONS, "transactions");
        assert_eq!(CheckpointResponseField::EVENTS, "events");
    }

    #[test]
    fn checkpoint_event_field_paths() {
        assert_eq!(CheckpointEventField::ALL, "events");
        assert_eq!(CheckpointEventField::BCS, "events.bcs");
        assert_eq!(CheckpointEventField::PACKAGE_ID, "events.package_id");
    }

    #[test]
    fn simulate_field_paths() {
        assert_eq!(SimulateField::ALL, "*");
        assert_eq!(SimulateField::SUGGESTED_GAS_PRICE, "suggested_gas_price");
        assert_eq!(
            SimulateField::EXECUTION_RESULT_COMMAND_RESULTS,
            "execution_result.command_results"
        );
        assert_eq!(
            SimulateField::EXECUTION_RESULT_EXECUTION_ERROR_BCS_KIND,
            "execution_result.execution_error.bcs_kind"
        );
    }

    #[test]
    fn dynamic_field_field_paths() {
        assert_eq!(DynamicFieldField::ALL, "*");
        assert_eq!(DynamicFieldField::KIND, "kind");
        assert_eq!(DynamicFieldField::NAME, "name");
        assert_eq!(DynamicFieldField::CHILD_OBJECT, "child_object");
    }
}
