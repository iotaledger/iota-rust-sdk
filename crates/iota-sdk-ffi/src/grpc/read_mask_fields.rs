// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Typed read mask fields, one enum per endpoint.
//!
//! Each enum mirrors the field namespace the Rust client defines for the same
//! endpoint in `iota_sdk::grpc_client::read_mask_fields`, so the field paths
//! themselves are defined only there. The `read_mask` parameter of a method
//! takes a list of the matching enum; `None` selects the endpoint's default
//! mask. Every enum has a `Custom` variant taking a raw field path, for paths
//! that have no variant of their own.

use iota_sdk::grpc_client::read_mask_fields as sdk;

/// A typed read mask field mirroring one of the Rust client's field
/// namespaces.
pub(crate) trait ReadMaskField: Sized {
    /// The Rust client's field type this enum maps onto.
    type Field: AsRef<str> + From<Self>;
}

/// Define a read mask field enum with one variant per listed constant of the
/// Rust client's field namespace of the same name, named after the constant
/// in PascalCase.
///
/// The optional `keyed` block adds variants carrying a map key, each mapped
/// onto the namespace's constructor of that name.
macro_rules! read_mask_fields {
    (
        $(#[$attr:meta])*
        pub enum $name:ident {
            $(
                $(#[$variant_attr:meta])*
                $path:ident
            ),* $(,)?
        }
        $(
            keyed {
                $(
                    $(#[$keyed_attr:meta])*
                    $keyed:ident => $constructor:ident
                ),* $(,)?
            }
        )?
    ) => {
        paste::paste! {
            $(#[$attr])*
            #[derive(Clone, Debug, uniffi::Enum)]
            pub enum $name {
                $(
                    $(#[$variant_attr])*
                    [<$path:camel>],
                )*
                $($(
                    $(#[$keyed_attr])*
                    $keyed { key: String },
                )*)?
                /// A raw field path, for paths that have no variant of their own.
                Custom { path: String },
            }

            impl From<$name> for sdk::$name {
                fn from(field: $name) -> Self {
                    match field {
                        $($name::[<$path:camel>] => Self::$path,)*
                        $($($name::$keyed { key } => Self::$constructor(&key),)*)?
                        $name::Custom { path } => Self::custom(path),
                    }
                }
            }

            #[cfg(test)]
            impl $name {
                const VARIANTS: &'static [Self] = &[$(Self::[<$path:camel>],)*];
            }
        }

        impl ReadMaskField for $name {
            type Field = sdk::$name;
        }
    };
}

read_mask_fields! {
    /// Field paths for `objects` and `objects_with_versions`.
    pub enum ObjectField {
        /// Wildcard — request all object fields.
        ALL,
        /// Object reference (object_id, version, digest).
        REFERENCE,
        /// The object ID.
        REFERENCE_OBJECT_ID,
        /// The object version.
        REFERENCE_VERSION,
        /// The object content digest.
        REFERENCE_DIGEST,
        /// The full BCS-encoded object.
        BCS,
    }
}

read_mask_fields! {
    /// Field paths for `owned_objects` and `all_owned_objects`.
    pub enum OwnedObjectField {
        /// Wildcard — request all fields.
        ALL,
        /// Object reference (object_id, version, digest).
        REFERENCE,
        /// The object ID.
        REFERENCE_OBJECT_ID,
        /// The object version.
        REFERENCE_VERSION,
        /// The object content digest.
        REFERENCE_DIGEST,
        /// The full BCS-encoded object.
        BCS,
    }
}

read_mask_fields! {
    /// Field paths for `transactions`, `execute_transaction` and
    /// `execute_transactions`.
    pub enum TransactionField {
        /// Wildcard — request all fields.
        ALL,
        /// Transaction data (all sub-fields).
        TRANSACTION,
        /// The transaction digest.
        TRANSACTION_DIGEST,
        /// The full BCS-encoded transaction.
        TRANSACTION_BCS,
        /// User signatures (all sub-fields).
        SIGNATURES,
        /// The full BCS-encoded signatures.
        SIGNATURES_BCS,
        /// Transaction effects (all sub-fields).
        EFFECTS,
        /// The effects digest.
        EFFECTS_DIGEST,
        /// The full BCS-encoded effects.
        EFFECTS_BCS,
        /// Transaction events (all sub-fields).
        EVENTS,
        /// The events digest.
        EVENTS_DIGEST,
        /// Individual events (all sub-fields).
        EVENTS_EVENTS,
        /// Full BCS-encoded event.
        EVENTS_EVENTS_BCS,
        /// The ID of the package that emitted the event.
        EVENTS_EVENTS_PACKAGE_ID,
        /// The module that emitted the event.
        EVENTS_EVENTS_MODULE,
        /// The sender that triggered the event.
        EVENTS_EVENTS_SENDER,
        /// The type of the event.
        EVENTS_EVENTS_EVENT_TYPE,
        /// The full BCS-encoded contents of the event.
        EVENTS_EVENTS_BCS_CONTENTS,
        /// The JSON-encoded contents of the event.
        EVENTS_EVENTS_JSON_CONTENTS,
        /// Checkpoint sequence number that included the transaction.
        CHECKPOINT,
        /// Timestamp of the checkpoint that included the transaction.
        TIMESTAMP,
        /// Input objects (all sub-fields).
        INPUT_OBJECTS,
        /// Input object reference (object_id, version, digest).
        INPUT_OBJECTS_REFERENCE,
        /// Input object ID.
        INPUT_OBJECTS_REFERENCE_OBJECT_ID,
        /// Input object version.
        INPUT_OBJECTS_REFERENCE_VERSION,
        /// Input object digest.
        INPUT_OBJECTS_REFERENCE_DIGEST,
        /// The full BCS-encoded input object.
        INPUT_OBJECTS_BCS,
        /// Output objects (all sub-fields).
        OUTPUT_OBJECTS,
        /// Output object reference (object_id, version, digest).
        OUTPUT_OBJECTS_REFERENCE,
        /// Output object ID.
        OUTPUT_OBJECTS_REFERENCE_OBJECT_ID,
        /// Output object version.
        OUTPUT_OBJECTS_REFERENCE_VERSION,
        /// Output object digest.
        OUTPUT_OBJECTS_REFERENCE_DIGEST,
        /// The full BCS-encoded output object.
        OUTPUT_OBJECTS_BCS,
        /// Balance changes (all sub-fields).
        BALANCE_CHANGES,
        /// The owner whose balance changed.
        BALANCE_CHANGES_OWNER,
        /// The coin type of the balance change.
        BALANCE_CHANGES_COIN_TYPE,
        /// The signed amount of the balance change.
        BALANCE_CHANGES_AMOUNT,
        /// Object changes (all sub-fields).
        OBJECT_CHANGES,
        /// Published-package object changes.
        OBJECT_CHANGES_PUBLISHED,
        /// Mutated-object changes.
        OBJECT_CHANGES_MUTATED,
        /// Deleted-object changes.
        OBJECT_CHANGES_DELETED,
        /// Wrapped-object changes.
        OBJECT_CHANGES_WRAPPED,
        /// Unwrapped-object changes.
        OBJECT_CHANGES_UNWRAPPED,
        /// Created-object changes.
        OBJECT_CHANGES_CREATED,
    }
}

read_mask_fields! {
    /// Field paths for `service_info`.
    pub enum ServiceInfoField {
        /// Wildcard — request all fields.
        ALL,
        /// The chain ID (network identifier).
        CHAIN_ID,
        /// The chain identifier string.
        CHAIN,
        /// The current epoch.
        EPOCH,
        /// Height of the last executed checkpoint.
        EXECUTED_CHECKPOINT_HEIGHT,
        /// Timestamp of the last executed checkpoint.
        EXECUTED_CHECKPOINT_TIMESTAMP,
        /// Lowest available checkpoint for transaction/checkpoint data.
        LOWEST_AVAILABLE_CHECKPOINT,
        /// Lowest available checkpoint for object data.
        LOWEST_AVAILABLE_CHECKPOINT_OBJECTS,
        /// The server version.
        SERVER,
    }
}

read_mask_fields! {
    /// Field paths for `epoch`.
    pub enum EpochField {
        /// Wildcard — request all fields.
        ALL,
        /// The epoch number.
        EPOCH,
        /// The validator committee for this epoch.
        COMMITTEE,
        /// The BCS-encoded system state.
        BCS_SYSTEM_STATE,
        /// The first checkpoint in the epoch.
        FIRST_CHECKPOINT,
        /// The last checkpoint in the epoch.
        LAST_CHECKPOINT,
        /// The start timestamp of the epoch.
        START,
        /// The end timestamp of the epoch.
        END,
        /// The reference gas price during the epoch (in NANOS).
        REFERENCE_GAS_PRICE,
        /// All protocol configuration fields.
        PROTOCOL_CONFIG,
        /// The protocol version.
        PROTOCOL_CONFIG_PROTOCOL_VERSION,
        /// All feature flags.
        PROTOCOL_CONFIG_FEATURE_FLAGS,
        /// All protocol attributes.
        PROTOCOL_CONFIG_ATTRIBUTES,
        /// All epoch-close-proof fields.
        EPOCH_CLOSE_PROOF,
        /// The certified checkpoint that closed the epoch.
        EPOCH_CLOSE_PROOF_CHECKPOINT,
        /// Effects of the epoch-change transaction.
        EPOCH_CLOSE_PROOF_END_OF_EPOCH_TRANSACTION_EFFECTS,
        /// Events emitted by the epoch-change transaction.
        EPOCH_CLOSE_PROOF_END_OF_EPOCH_TRANSACTION_EVENTS,
        /// Raw BCS of the next epoch's start-of-epoch system-state objects.
        EPOCH_CLOSE_PROOF_BCS_NEXT_EPOCH_SYSTEM_STATE_OBJECTS,
    }
    keyed {
        /// A single feature flag, by key.
        ProtocolConfigFeatureFlag => feature_flag,
        /// A single protocol attribute, by key.
        ProtocolConfigAttribute => attribute,
    }
}

read_mask_fields! {
    /// Field paths for the checkpoint methods: `checkpoint_latest`,
    /// `checkpoint_by_sequence_number`, `checkpoint_by_digest`,
    /// `checkpoints_stream` and `checkpoints_stream_filtered`.
    pub enum CheckpointResponseField {
        /// Wildcard — request all fields.
        ALL,
        /// All checkpoint data fields.
        CHECKPOINT,
        /// The checkpoint sequence number.
        CHECKPOINT_SEQUENCE_NUMBER,
        /// Checkpoint summary (all sub-fields).
        CHECKPOINT_SUMMARY,
        /// The checkpoint summary digest.
        CHECKPOINT_SUMMARY_DIGEST,
        /// The full BCS-encoded checkpoint summary.
        CHECKPOINT_SUMMARY_BCS,
        /// Checkpoint contents (all sub-fields).
        CHECKPOINT_CONTENTS,
        /// The checkpoint contents digest.
        CHECKPOINT_CONTENTS_DIGEST,
        /// The full BCS-encoded checkpoint contents.
        CHECKPOINT_CONTENTS_BCS,
        /// The validator aggregated signature.
        CHECKPOINT_SIGNATURE,
        /// All transactions in the checkpoint.
        TRANSACTIONS,
        /// Transaction data of a checkpoint transaction (all sub-fields).
        TRANSACTIONS_TRANSACTION,
        /// The transaction digest.
        TRANSACTIONS_TRANSACTION_DIGEST,
        /// The full BCS-encoded transaction.
        TRANSACTIONS_TRANSACTION_BCS,
        /// User signatures (all sub-fields).
        TRANSACTIONS_SIGNATURES,
        /// The full BCS-encoded signatures.
        TRANSACTIONS_SIGNATURES_BCS,
        /// Transaction effects (all sub-fields).
        TRANSACTIONS_EFFECTS,
        /// The effects digest.
        TRANSACTIONS_EFFECTS_DIGEST,
        /// The full BCS-encoded effects.
        TRANSACTIONS_EFFECTS_BCS,
        /// Transaction events (all sub-fields).
        TRANSACTIONS_EVENTS,
        /// The events digest.
        TRANSACTIONS_EVENTS_DIGEST,
        /// Individual events — full BCS-encoded.
        TRANSACTIONS_EVENTS_EVENTS_BCS,
        /// Checkpoint sequence number of the transaction.
        TRANSACTIONS_CHECKPOINT,
        /// Timestamp of the transaction.
        TRANSACTIONS_TIMESTAMP,
        /// Input objects (all sub-fields).
        TRANSACTIONS_INPUT_OBJECTS,
        /// The full BCS-encoded input object.
        TRANSACTIONS_INPUT_OBJECTS_BCS,
        /// Output objects (all sub-fields).
        TRANSACTIONS_OUTPUT_OBJECTS,
        /// The full BCS-encoded output object.
        TRANSACTIONS_OUTPUT_OBJECTS_BCS,
        /// Balance changes (all sub-fields).
        TRANSACTIONS_BALANCE_CHANGES,
        /// Object changes (all sub-fields).
        TRANSACTIONS_OBJECT_CHANGES,
        /// All events in the checkpoint.
        EVENTS,
        /// Full BCS-encoded event.
        EVENTS_BCS,
        /// The ID of the package that emitted the event.
        EVENTS_PACKAGE_ID,
        /// The module that emitted the event.
        EVENTS_MODULE,
        /// The sender that triggered the event.
        EVENTS_SENDER,
        /// The type of the event.
        EVENTS_EVENT_TYPE,
        /// The full BCS-encoded contents of the event.
        EVENTS_BCS_CONTENTS,
        /// The JSON-encoded contents of the event.
        EVENTS_JSON_CONTENTS,
    }
}

read_mask_fields! {
    /// Field paths for `simulate_transaction` and `simulate_transactions`.
    pub enum SimulateField {
        /// Wildcard — request all fields.
        ALL,
        /// The simulated executed transaction (all sub-fields).
        EXECUTED_TRANSACTION,
        /// Transaction data of the executed transaction (all sub-fields).
        EXECUTED_TRANSACTION_TRANSACTION,
        /// The transaction digest.
        EXECUTED_TRANSACTION_TRANSACTION_DIGEST,
        /// The full BCS-encoded transaction.
        EXECUTED_TRANSACTION_TRANSACTION_BCS,
        /// User signatures (all sub-fields).
        EXECUTED_TRANSACTION_SIGNATURES,
        /// The full BCS-encoded signatures.
        EXECUTED_TRANSACTION_SIGNATURES_BCS,
        /// Transaction effects (all sub-fields).
        EXECUTED_TRANSACTION_EFFECTS,
        /// The effects digest.
        EXECUTED_TRANSACTION_EFFECTS_DIGEST,
        /// The full BCS-encoded effects.
        EXECUTED_TRANSACTION_EFFECTS_BCS,
        /// Transaction events (all sub-fields).
        EXECUTED_TRANSACTION_EVENTS,
        /// The events digest.
        EXECUTED_TRANSACTION_EVENTS_DIGEST,
        /// Individual events — full BCS-encoded.
        EXECUTED_TRANSACTION_EVENTS_EVENTS_BCS,
        /// Checkpoint sequence number that included the transaction.
        EXECUTED_TRANSACTION_CHECKPOINT,
        /// Timestamp of the transaction.
        EXECUTED_TRANSACTION_TIMESTAMP,
        /// Input objects (all sub-fields).
        EXECUTED_TRANSACTION_INPUT_OBJECTS,
        /// The full BCS-encoded input object.
        EXECUTED_TRANSACTION_INPUT_OBJECTS_BCS,
        /// Output objects (all sub-fields).
        EXECUTED_TRANSACTION_OUTPUT_OBJECTS,
        /// The full BCS-encoded output object.
        EXECUTED_TRANSACTION_OUTPUT_OBJECTS_BCS,
        /// Balance changes (all sub-fields).
        EXECUTED_TRANSACTION_BALANCE_CHANGES,
        /// Object changes (all sub-fields).
        EXECUTED_TRANSACTION_OBJECT_CHANGES,
        /// The suggested gas price (in NANOS).
        SUGGESTED_GAS_PRICE,
        /// Execution result (all sub-fields).
        EXECUTION_RESULT,
        /// Per-command results (on success, all sub-fields).
        EXECUTION_RESULT_COMMAND_RESULTS,
        /// Objects mutated by reference.
        EXECUTION_RESULT_COMMAND_RESULTS_MUTATED_BY_REF,
        /// Return values from the command.
        EXECUTION_RESULT_COMMAND_RESULTS_RETURN_VALUES,
        /// Execution error details (on failure, all sub-fields).
        EXECUTION_RESULT_EXECUTION_ERROR,
        /// The BCS-encoded error kind.
        EXECUTION_RESULT_EXECUTION_ERROR_BCS_KIND,
        /// The error source description.
        EXECUTION_RESULT_EXECUTION_ERROR_SOURCE,
        /// The index of the command that failed.
        EXECUTION_RESULT_EXECUTION_ERROR_COMMAND_INDEX,
    }
}

read_mask_fields! {
    /// Field paths for `view_function_call` and `view_function_calls`.
    pub enum ViewFunctionCallField {
        /// Wildcard — request all fields.
        ALL,
        /// Execution result (all sub-fields).
        EXECUTION_RESULT,
        /// Return values of the call (all sub-fields).
        EXECUTION_RESULT_RETURN_VALUES,
        /// The argument each return value came from.
        EXECUTION_RESULT_RETURN_VALUES_ARGUMENT,
        /// The Move type of each return value.
        EXECUTION_RESULT_RETURN_VALUES_TYPE_TAG,
        /// The BCS-encoded return values.
        EXECUTION_RESULT_RETURN_VALUES_BCS,
        /// The return values rendered as JSON.
        EXECUTION_RESULT_RETURN_VALUES_JSON,
        /// Execution error details (on failure, all sub-fields).
        EXECUTION_RESULT_EXECUTION_ERROR,
        /// The BCS-encoded error kind.
        EXECUTION_RESULT_EXECUTION_ERROR_BCS_KIND,
        /// The error source description.
        EXECUTION_RESULT_EXECUTION_ERROR_SOURCE,
        /// The index of the command that failed.
        EXECUTION_RESULT_EXECUTION_ERROR_COMMAND_INDEX,
    }
}

read_mask_fields! {
    /// Field paths for `dynamic_fields` and `all_dynamic_fields`.
    pub enum DynamicFieldField {
        /// Wildcard — request all fields.
        ALL,
        /// The kind of dynamic field (field or object).
        KIND,
        /// The parent object ID.
        PARENT,
        /// The field object ID.
        FIELD_ID,
        /// The child object ID (for dynamic object fields).
        CHILD_ID,
        /// BCS-encoded field name.
        NAME,
        /// BCS-encoded field value.
        VALUE,
        /// The Move type of the value.
        VALUE_TYPE,
        /// The full field object (sub-fields match `objects`).
        FIELD_OBJECT,
        /// The full child object (sub-fields match `objects`).
        CHILD_OBJECT,
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use super::*;

    /// The variant name of each field is the PascalCase form of its path, so
    /// a Rust client constant named differently from its path shows up here.
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

    #[test]
    fn keyed_and_custom_variants_map_onto_their_paths() {
        let path = |field: EpochField| sdk::EpochField::from(field).as_str().to_owned();
        assert_eq!(
            path(EpochField::ProtocolConfigFeatureFlag {
                key: "enable_vdf".to_owned()
            }),
            "protocol_config.feature_flags.enable_vdf"
        );
        assert_eq!(
            path(EpochField::ProtocolConfigAttribute {
                key: "max_tx_gas".to_owned()
            }),
            "protocol_config.attributes.max_tx_gas"
        );
        assert_eq!(
            sdk::DynamicFieldField::from(DynamicFieldField::Custom {
                path: "field_object.bcs".to_owned()
            })
            .as_str(),
            "field_object.bcs"
        );
    }
}
