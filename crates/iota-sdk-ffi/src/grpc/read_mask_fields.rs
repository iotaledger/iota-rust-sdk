// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Typed read mask fields, one enum per endpoint.
//!
//! Each enum mirrors the field namespace the Rust client defines for the same
//! endpoint in `iota_sdk::grpc_client::read_mask_fields`, so the field paths
//! themselves are defined only there. The `read_mask` parameter of a method
//! takes a list of the matching enum; `None` selects the endpoint's default
//! mask.

use iota_sdk::grpc_client::read_mask_fields as sdk;

/// A typed read mask field mirroring one of the Rust client's field
/// namespaces.
pub(crate) trait ReadMaskField: Sized {
    /// The Rust client's field type this enum maps onto.
    type Field: AsRef<str> + From<Self>;
}

/// Define a read mask field enum whose variants map one-to-one onto the
/// constants of the Rust client's field namespace of the same name.
macro_rules! read_mask_fields {
    (
        $(#[$attr:meta])*
        pub enum $name:ident {
            $(
                $(#[$variant_attr:meta])*
                $variant:ident => $path:ident
            ),* $(,)?
        }
    ) => {
        $(#[$attr])*
        #[derive(Clone, Debug, uniffi::Enum)]
        pub enum $name {
            $(
                $(#[$variant_attr])*
                $variant,
            )*
        }

        impl From<$name> for sdk::$name {
            fn from(field: $name) -> Self {
                match field {
                    $($name::$variant => Self::$path,)*
                }
            }
        }

        impl ReadMaskField for $name {
            type Field = sdk::$name;
        }

        #[cfg(test)]
        impl $name {
            const VARIANTS: &'static [Self] = &[$(Self::$variant,)*];
        }
    };
}

read_mask_fields! {
    /// Field paths for `objects` and `objects_with_versions`.
    pub enum ObjectField {
        /// Wildcard — request all object fields.
        All => ALL,
        /// Object reference (object_id, version, digest).
        Reference => REFERENCE,
        /// The object ID.
        ReferenceObjectId => REFERENCE_OBJECT_ID,
        /// The object version.
        ReferenceVersion => REFERENCE_VERSION,
        /// The object content digest.
        ReferenceDigest => REFERENCE_DIGEST,
        /// The full BCS-encoded object.
        Bcs => BCS,
    }
}

read_mask_fields! {
    /// Field paths for `owned_objects` and `all_owned_objects`.
    pub enum OwnedObjectField {
        /// Wildcard — request all fields.
        All => ALL,
        /// Object reference (object_id, version, digest).
        Reference => REFERENCE,
        /// The object ID.
        ReferenceObjectId => REFERENCE_OBJECT_ID,
        /// The object version.
        ReferenceVersion => REFERENCE_VERSION,
        /// The object content digest.
        ReferenceDigest => REFERENCE_DIGEST,
        /// The full BCS-encoded object.
        Bcs => BCS,
    }
}

read_mask_fields! {
    /// Field paths for `transactions`, `execute_transaction` and
    /// `execute_transactions`.
    pub enum TransactionField {
        /// Wildcard — request all fields.
        All => ALL,
        /// Transaction data (all sub-fields).
        Transaction => TRANSACTION,
        /// The transaction digest.
        TransactionDigest => TRANSACTION_DIGEST,
        /// The full BCS-encoded transaction.
        TransactionBcs => TRANSACTION_BCS,
        /// User signatures (all sub-fields).
        Signatures => SIGNATURES,
        /// The full BCS-encoded signatures.
        SignaturesBcs => SIGNATURES_BCS,
        /// Transaction effects (all sub-fields).
        Effects => EFFECTS,
        /// The effects digest.
        EffectsDigest => EFFECTS_DIGEST,
        /// The full BCS-encoded effects.
        EffectsBcs => EFFECTS_BCS,
        /// Transaction events (all sub-fields).
        Events => EVENTS,
        /// The events digest.
        EventsDigest => EVENTS_DIGEST,
        /// Individual events (all sub-fields).
        EventsEvents => EVENTS_EVENTS,
        /// Full BCS-encoded event.
        EventsEventsBcs => EVENTS_EVENTS_BCS,
        /// The ID of the package that emitted the event.
        EventsEventsPackageId => EVENTS_EVENTS_PACKAGE_ID,
        /// The module that emitted the event.
        EventsEventsModule => EVENTS_EVENTS_MODULE,
        /// The sender that triggered the event.
        EventsEventsSender => EVENTS_EVENTS_SENDER,
        /// The type of the event.
        EventsEventsEventType => EVENTS_EVENTS_EVENT_TYPE,
        /// The full BCS-encoded contents of the event.
        EventsEventsBcsContents => EVENTS_EVENTS_BCS_CONTENTS,
        /// The JSON-encoded contents of the event.
        EventsEventsJsonContents => EVENTS_EVENTS_JSON_CONTENTS,
        /// Checkpoint sequence number that included the transaction.
        Checkpoint => CHECKPOINT,
        /// Timestamp of the checkpoint that included the transaction.
        Timestamp => TIMESTAMP,
        /// Input objects (all sub-fields).
        InputObjects => INPUT_OBJECTS,
        /// Input object reference (object_id, version, digest).
        InputObjectsReference => INPUT_OBJECTS_REFERENCE,
        /// Input object ID.
        InputObjectsReferenceObjectId => INPUT_OBJECTS_REFERENCE_OBJECT_ID,
        /// Input object version.
        InputObjectsReferenceVersion => INPUT_OBJECTS_REFERENCE_VERSION,
        /// Input object digest.
        InputObjectsReferenceDigest => INPUT_OBJECTS_REFERENCE_DIGEST,
        /// The full BCS-encoded input object.
        InputObjectsBcs => INPUT_OBJECTS_BCS,
        /// Output objects (all sub-fields).
        OutputObjects => OUTPUT_OBJECTS,
        /// Output object reference (object_id, version, digest).
        OutputObjectsReference => OUTPUT_OBJECTS_REFERENCE,
        /// Output object ID.
        OutputObjectsReferenceObjectId => OUTPUT_OBJECTS_REFERENCE_OBJECT_ID,
        /// Output object version.
        OutputObjectsReferenceVersion => OUTPUT_OBJECTS_REFERENCE_VERSION,
        /// Output object digest.
        OutputObjectsReferenceDigest => OUTPUT_OBJECTS_REFERENCE_DIGEST,
        /// The full BCS-encoded output object.
        OutputObjectsBcs => OUTPUT_OBJECTS_BCS,
        /// Balance changes (all sub-fields).
        BalanceChanges => BALANCE_CHANGES,
        /// The owner whose balance changed.
        BalanceChangesOwner => BALANCE_CHANGES_OWNER,
        /// The coin type of the balance change.
        BalanceChangesCoinType => BALANCE_CHANGES_COIN_TYPE,
        /// The signed amount of the balance change.
        BalanceChangesAmount => BALANCE_CHANGES_AMOUNT,
        /// Object changes (all sub-fields).
        ObjectChanges => OBJECT_CHANGES,
        /// Published-package object changes.
        ObjectChangesPublished => OBJECT_CHANGES_PUBLISHED,
        /// Mutated-object changes.
        ObjectChangesMutated => OBJECT_CHANGES_MUTATED,
        /// Deleted-object changes.
        ObjectChangesDeleted => OBJECT_CHANGES_DELETED,
        /// Wrapped-object changes.
        ObjectChangesWrapped => OBJECT_CHANGES_WRAPPED,
        /// Unwrapped-object changes.
        ObjectChangesUnwrapped => OBJECT_CHANGES_UNWRAPPED,
        /// Created-object changes.
        ObjectChangesCreated => OBJECT_CHANGES_CREATED,
    }
}

read_mask_fields! {
    /// Field paths for `service_info`.
    pub enum ServiceInfoField {
        /// Wildcard — request all fields.
        All => ALL,
        /// The chain ID (network identifier).
        ChainId => CHAIN_ID,
        /// The chain identifier string.
        Chain => CHAIN,
        /// The current epoch.
        Epoch => EPOCH,
        /// Height of the last executed checkpoint.
        ExecutedCheckpointHeight => EXECUTED_CHECKPOINT_HEIGHT,
        /// Timestamp of the last executed checkpoint.
        ExecutedCheckpointTimestamp => EXECUTED_CHECKPOINT_TIMESTAMP,
        /// Lowest available checkpoint for transaction/checkpoint data.
        LowestAvailableCheckpoint => LOWEST_AVAILABLE_CHECKPOINT,
        /// Lowest available checkpoint for object data.
        LowestAvailableCheckpointObjects => LOWEST_AVAILABLE_CHECKPOINT_OBJECTS,
        /// The server version.
        Server => SERVER,
    }
}

read_mask_fields! {
    /// Field paths for `epoch`.
    pub enum EpochField {
        /// Wildcard — request all fields.
        All => ALL,
        /// The epoch number.
        Epoch => EPOCH,
        /// The validator committee for this epoch.
        Committee => COMMITTEE,
        /// The BCS-encoded system state.
        BcsSystemState => BCS_SYSTEM_STATE,
        /// The first checkpoint in the epoch.
        FirstCheckpoint => FIRST_CHECKPOINT,
        /// The last checkpoint in the epoch.
        LastCheckpoint => LAST_CHECKPOINT,
        /// The start timestamp of the epoch.
        Start => START,
        /// The end timestamp of the epoch.
        End => END,
        /// The reference gas price during the epoch (in NANOS).
        ReferenceGasPrice => REFERENCE_GAS_PRICE,
        /// All protocol configuration fields.
        ProtocolConfig => PROTOCOL_CONFIG,
        /// The protocol version.
        ProtocolConfigProtocolVersion => PROTOCOL_CONFIG_PROTOCOL_VERSION,
        /// All feature flags.
        ProtocolConfigFeatureFlags => PROTOCOL_CONFIG_FEATURE_FLAGS,
        /// All protocol attributes.
        ProtocolConfigAttributes => PROTOCOL_CONFIG_ATTRIBUTES,
        /// All epoch-close-proof fields.
        EpochCloseProof => EPOCH_CLOSE_PROOF,
        /// The certified checkpoint that closed the epoch.
        EpochCloseProofCheckpoint => EPOCH_CLOSE_PROOF_CHECKPOINT,
        /// Effects of the epoch-change transaction.
        EpochCloseProofEndOfEpochTransactionEffects =>
            EPOCH_CLOSE_PROOF_END_OF_EPOCH_TRANSACTION_EFFECTS,
        /// Events emitted by the epoch-change transaction.
        EpochCloseProofEndOfEpochTransactionEvents =>
            EPOCH_CLOSE_PROOF_END_OF_EPOCH_TRANSACTION_EVENTS,
        /// Raw BCS of the next epoch's start-of-epoch system-state objects.
        EpochCloseProofBcsNextEpochSystemStateObjects =>
            EPOCH_CLOSE_PROOF_BCS_NEXT_EPOCH_SYSTEM_STATE_OBJECTS,
    }
}

read_mask_fields! {
    /// Field paths for the checkpoint methods: `checkpoint_latest`,
    /// `checkpoint_by_sequence_number`, `checkpoint_by_digest`,
    /// `checkpoints_stream` and `checkpoints_stream_filtered`.
    pub enum CheckpointResponseField {
        /// Wildcard — request all fields.
        All => ALL,
        /// All checkpoint data fields.
        Checkpoint => CHECKPOINT,
        /// The checkpoint sequence number.
        CheckpointSequenceNumber => CHECKPOINT_SEQUENCE_NUMBER,
        /// Checkpoint summary (all sub-fields).
        CheckpointSummary => CHECKPOINT_SUMMARY,
        /// The checkpoint summary digest.
        CheckpointSummaryDigest => CHECKPOINT_SUMMARY_DIGEST,
        /// The full BCS-encoded checkpoint summary.
        CheckpointSummaryBcs => CHECKPOINT_SUMMARY_BCS,
        /// Checkpoint contents (all sub-fields).
        CheckpointContents => CHECKPOINT_CONTENTS,
        /// The checkpoint contents digest.
        CheckpointContentsDigest => CHECKPOINT_CONTENTS_DIGEST,
        /// The full BCS-encoded checkpoint contents.
        CheckpointContentsBcs => CHECKPOINT_CONTENTS_BCS,
        /// The validator aggregated signature.
        CheckpointSignature => CHECKPOINT_SIGNATURE,
        /// All transactions in the checkpoint.
        Transactions => TRANSACTIONS,
        /// Transaction data of a checkpoint transaction (all sub-fields).
        TransactionsTransaction => TRANSACTIONS_TRANSACTION,
        /// The transaction digest.
        TransactionsTransactionDigest => TRANSACTIONS_TRANSACTION_DIGEST,
        /// The full BCS-encoded transaction.
        TransactionsTransactionBcs => TRANSACTIONS_TRANSACTION_BCS,
        /// User signatures (all sub-fields).
        TransactionsSignatures => TRANSACTIONS_SIGNATURES,
        /// The full BCS-encoded signatures.
        TransactionsSignaturesBcs => TRANSACTIONS_SIGNATURES_BCS,
        /// Transaction effects (all sub-fields).
        TransactionsEffects => TRANSACTIONS_EFFECTS,
        /// The effects digest.
        TransactionsEffectsDigest => TRANSACTIONS_EFFECTS_DIGEST,
        /// The full BCS-encoded effects.
        TransactionsEffectsBcs => TRANSACTIONS_EFFECTS_BCS,
        /// Transaction events (all sub-fields).
        TransactionsEvents => TRANSACTIONS_EVENTS,
        /// The events digest.
        TransactionsEventsDigest => TRANSACTIONS_EVENTS_DIGEST,
        /// Individual events — full BCS-encoded.
        TransactionsEventsEventsBcs => TRANSACTIONS_EVENTS_EVENTS_BCS,
        /// Checkpoint sequence number of the transaction.
        TransactionsCheckpoint => TRANSACTIONS_CHECKPOINT,
        /// Timestamp of the transaction.
        TransactionsTimestamp => TRANSACTIONS_TIMESTAMP,
        /// Input objects (all sub-fields).
        TransactionsInputObjects => TRANSACTIONS_INPUT_OBJECTS,
        /// The full BCS-encoded input object.
        TransactionsInputObjectsBcs => TRANSACTIONS_INPUT_OBJECTS_BCS,
        /// Output objects (all sub-fields).
        TransactionsOutputObjects => TRANSACTIONS_OUTPUT_OBJECTS,
        /// The full BCS-encoded output object.
        TransactionsOutputObjectsBcs => TRANSACTIONS_OUTPUT_OBJECTS_BCS,
        /// Balance changes (all sub-fields).
        TransactionsBalanceChanges => TRANSACTIONS_BALANCE_CHANGES,
        /// Object changes (all sub-fields).
        TransactionsObjectChanges => TRANSACTIONS_OBJECT_CHANGES,
        /// All events in the checkpoint.
        Events => EVENTS,
        /// Full BCS-encoded event.
        EventsBcs => EVENTS_BCS,
        /// The ID of the package that emitted the event.
        EventsPackageId => EVENTS_PACKAGE_ID,
        /// The module that emitted the event.
        EventsModule => EVENTS_MODULE,
        /// The sender that triggered the event.
        EventsSender => EVENTS_SENDER,
        /// The type of the event.
        EventsEventType => EVENTS_EVENT_TYPE,
        /// The full BCS-encoded contents of the event.
        EventsBcsContents => EVENTS_BCS_CONTENTS,
        /// The JSON-encoded contents of the event.
        EventsJsonContents => EVENTS_JSON_CONTENTS,
    }
}

read_mask_fields! {
    /// Field paths for `simulate_transaction` and `simulate_transactions`.
    pub enum SimulateField {
        /// Wildcard — request all fields.
        All => ALL,
        /// The simulated executed transaction (all sub-fields).
        ExecutedTransaction => EXECUTED_TRANSACTION,
        /// Transaction data of the executed transaction (all sub-fields).
        ExecutedTransactionTransaction => EXECUTED_TRANSACTION_TRANSACTION,
        /// The transaction digest.
        ExecutedTransactionTransactionDigest => EXECUTED_TRANSACTION_TRANSACTION_DIGEST,
        /// The full BCS-encoded transaction.
        ExecutedTransactionTransactionBcs => EXECUTED_TRANSACTION_TRANSACTION_BCS,
        /// User signatures (all sub-fields).
        ExecutedTransactionSignatures => EXECUTED_TRANSACTION_SIGNATURES,
        /// The full BCS-encoded signatures.
        ExecutedTransactionSignaturesBcs => EXECUTED_TRANSACTION_SIGNATURES_BCS,
        /// Transaction effects (all sub-fields).
        ExecutedTransactionEffects => EXECUTED_TRANSACTION_EFFECTS,
        /// The effects digest.
        ExecutedTransactionEffectsDigest => EXECUTED_TRANSACTION_EFFECTS_DIGEST,
        /// The full BCS-encoded effects.
        ExecutedTransactionEffectsBcs => EXECUTED_TRANSACTION_EFFECTS_BCS,
        /// Transaction events (all sub-fields).
        ExecutedTransactionEvents => EXECUTED_TRANSACTION_EVENTS,
        /// The events digest.
        ExecutedTransactionEventsDigest => EXECUTED_TRANSACTION_EVENTS_DIGEST,
        /// Individual events — full BCS-encoded.
        ExecutedTransactionEventsEventsBcs => EXECUTED_TRANSACTION_EVENTS_EVENTS_BCS,
        /// Checkpoint sequence number that included the transaction.
        ExecutedTransactionCheckpoint => EXECUTED_TRANSACTION_CHECKPOINT,
        /// Timestamp of the transaction.
        ExecutedTransactionTimestamp => EXECUTED_TRANSACTION_TIMESTAMP,
        /// Input objects (all sub-fields).
        ExecutedTransactionInputObjects => EXECUTED_TRANSACTION_INPUT_OBJECTS,
        /// The full BCS-encoded input object.
        ExecutedTransactionInputObjectsBcs => EXECUTED_TRANSACTION_INPUT_OBJECTS_BCS,
        /// Output objects (all sub-fields).
        ExecutedTransactionOutputObjects => EXECUTED_TRANSACTION_OUTPUT_OBJECTS,
        /// The full BCS-encoded output object.
        ExecutedTransactionOutputObjectsBcs => EXECUTED_TRANSACTION_OUTPUT_OBJECTS_BCS,
        /// Balance changes (all sub-fields).
        ExecutedTransactionBalanceChanges => EXECUTED_TRANSACTION_BALANCE_CHANGES,
        /// Object changes (all sub-fields).
        ExecutedTransactionObjectChanges => EXECUTED_TRANSACTION_OBJECT_CHANGES,
        /// The suggested gas price (in NANOS).
        SuggestedGasPrice => SUGGESTED_GAS_PRICE,
        /// Execution result (all sub-fields).
        ExecutionResult => EXECUTION_RESULT,
        /// Per-command results (on success, all sub-fields).
        ExecutionResultCommandResults => EXECUTION_RESULT_COMMAND_RESULTS,
        /// Objects mutated by reference.
        ExecutionResultCommandResultsMutatedByRef =>
            EXECUTION_RESULT_COMMAND_RESULTS_MUTATED_BY_REF,
        /// Return values from the command.
        ExecutionResultCommandResultsReturnValues =>
            EXECUTION_RESULT_COMMAND_RESULTS_RETURN_VALUES,
        /// Execution error details (on failure, all sub-fields).
        ExecutionResultExecutionError => EXECUTION_RESULT_EXECUTION_ERROR,
        /// The BCS-encoded error kind.
        ExecutionResultExecutionErrorBcsKind => EXECUTION_RESULT_EXECUTION_ERROR_BCS_KIND,
        /// The error source description.
        ExecutionResultExecutionErrorSource => EXECUTION_RESULT_EXECUTION_ERROR_SOURCE,
        /// The index of the command that failed.
        ExecutionResultExecutionErrorCommandIndex =>
            EXECUTION_RESULT_EXECUTION_ERROR_COMMAND_INDEX,
    }
}

read_mask_fields! {
    /// Field paths for `view_function_call` and `view_function_calls`.
    pub enum ViewFunctionCallField {
        /// Wildcard — request all fields.
        All => ALL,
        /// Execution result (all sub-fields).
        ExecutionResult => EXECUTION_RESULT,
        /// Return values of the call (all sub-fields).
        ExecutionResultReturnValues => EXECUTION_RESULT_RETURN_VALUES,
        /// The argument each return value came from.
        ExecutionResultReturnValuesArgument => EXECUTION_RESULT_RETURN_VALUES_ARGUMENT,
        /// The Move type of each return value.
        ExecutionResultReturnValuesTypeTag => EXECUTION_RESULT_RETURN_VALUES_TYPE_TAG,
        /// The BCS-encoded return values.
        ExecutionResultReturnValuesBcs => EXECUTION_RESULT_RETURN_VALUES_BCS,
        /// The return values rendered as JSON.
        ExecutionResultReturnValuesJson => EXECUTION_RESULT_RETURN_VALUES_JSON,
        /// Execution error details (on failure, all sub-fields).
        ExecutionResultExecutionError => EXECUTION_RESULT_EXECUTION_ERROR,
        /// The BCS-encoded error kind.
        ExecutionResultExecutionErrorBcsKind => EXECUTION_RESULT_EXECUTION_ERROR_BCS_KIND,
        /// The error source description.
        ExecutionResultExecutionErrorSource => EXECUTION_RESULT_EXECUTION_ERROR_SOURCE,
        /// The index of the command that failed.
        ExecutionResultExecutionErrorCommandIndex =>
            EXECUTION_RESULT_EXECUTION_ERROR_COMMAND_INDEX,
    }
}

read_mask_fields! {
    /// Field paths for `dynamic_fields` and `all_dynamic_fields`.
    pub enum DynamicFieldField {
        /// Wildcard — request all fields.
        All => ALL,
        /// The kind of dynamic field (field or object).
        Kind => KIND,
        /// The parent object ID.
        Parent => PARENT,
        /// The field object ID.
        FieldId => FIELD_ID,
        /// The child object ID (for dynamic object fields).
        ChildId => CHILD_ID,
        /// BCS-encoded field name.
        Name => NAME,
        /// BCS-encoded field value.
        Value => VALUE,
        /// The Move type of the value.
        ValueType => VALUE_TYPE,
        /// The full field object (sub-fields match `objects`).
        FieldObject => FIELD_OBJECT,
        /// The full child object (sub-fields match `objects`).
        ChildObject => CHILD_OBJECT,
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use super::*;

    /// The variant name of each field is the PascalCase form of its path, so
    /// a variant wired to the wrong constant shows up here.
    fn variant_names_follow_their_paths<F>(variants: &[F])
    where
        F: ReadMaskField + Clone + Debug,
    {
        for variant in variants {
            let path = F::Field::from(variant.clone());
            let expected = match path.as_ref() {
                "*" => "All".to_owned(),
                path => path
                    .split(['.', '_'])
                    .map(|segment| {
                        let mut chars = segment.chars();
                        chars
                            .next()
                            .map(|first| first.to_ascii_uppercase())
                            .into_iter()
                            .chain(chars)
                            .collect::<String>()
                    })
                    .collect(),
            };
            assert_eq!(format!("{variant:?}"), expected);
        }
    }

    #[test]
    fn every_variant_maps_onto_its_path() {
        variant_names_follow_their_paths(ObjectField::VARIANTS);
        variant_names_follow_their_paths(OwnedObjectField::VARIANTS);
        variant_names_follow_their_paths(TransactionField::VARIANTS);
        variant_names_follow_their_paths(ServiceInfoField::VARIANTS);
        variant_names_follow_their_paths(EpochField::VARIANTS);
        variant_names_follow_their_paths(CheckpointResponseField::VARIANTS);
        variant_names_follow_their_paths(SimulateField::VARIANTS);
        variant_names_follow_their_paths(ViewFunctionCallField::VARIANTS);
        variant_names_follow_their_paths(DynamicFieldField::VARIANTS);
    }
}
