// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Typed read mask field paths and per-endpoint mask types.
//!
//! Each endpoint has a typed namespace (e.g. [`ObjectField`]) whose associated
//! constants identify the fields the server can return, and a matching
//! per-endpoint mask type (e.g. [`ObjectReadMask`]) that the client method
//! accepts. Use the mask's `default()` for the endpoint's default mask, or
//! build a mask from a single field, a slice, an array, or an owned vec of the
//! matching kind — conversion happens automatically:
//!
//! ```ignore
//! use iota_sdk_grpc_types::read_mask_fields::{ObjectField, ObjectReadMask};
//!
//! // Default mask.
//! client.get_objects([id], ObjectReadMask::default()).await?;
//!
//! // A single field.
//! client.get_objects([id], ObjectField::BCS).await?;
//!
//! // Multiple fields.
//! client
//!     .get_objects([id], [ObjectField::REFERENCE, ObjectField::BCS])
//!     .await?;
//! ```
//!
//! Mixing the wrong field type with the wrong endpoint is a compile error.

use std::borrow::Cow;

use crate::{
    field_mask_normalize,
    read_masks::{
        GET_CHECKPOINT_READ_MASK, GET_EPOCH_READ_MASK, GET_OBJECTS_READ_MASK,
        GET_SERVICE_INFO_READ_MASK, GET_TRANSACTIONS_READ_MASK, LIST_DYNAMIC_FIELDS_READ_MASK,
        LIST_OWNED_OBJECTS_READ_MASK, SIMULATE_TRANSACTIONS_READ_MASK,
    },
};

/// Conversion into an endpoint-scoped read mask.
///
/// This is the bound used by the client's `read_mask` parameters. It is
/// implemented for everything convertible into the endpoint's mask type: the
/// mask itself (e.g. `ObjectReadMask::default()` for the endpoint default), a
/// field constant of the matching field namespace (e.g. [`ObjectField::BCS`]),
/// arrays/slices/`Vec`s of such fields, and raw `&'static str`/`String` field
/// paths.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a valid read mask for this endpoint",
    label = "expected a value convertible into `{M}`",
    note = "accepted: `{M}` itself (e.g. `{M}::default()` for the endpoint default), \
            a field constant of the matching field namespace, an array/slice/`Vec` \
            of such fields, or a `&str`/`String` field path"
)]
pub trait IntoReadMask<M> {
    /// Convert `self` into the endpoint's read mask type.
    fn into_read_mask(self) -> M;
}

// =============================================================================
// Macros
// =============================================================================

macro_rules! define_field_paths {
    (
        $(#[$attr:meta])*
        pub struct $name:ident {
            $(
                $(#[$variant_attr:meta])*
                $variant:ident = $path:expr
            ),* $(,)?
        }
    ) => {
        $(#[$attr])*
        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        pub struct $name(Cow<'static, str>);

        impl $name {
            $(
                $(#[$variant_attr])*
                pub const $variant: Self = Self(Cow::Borrowed($path));
            )*

            /// Construct from a custom field path (escape hatch for paths not
            /// covered by the named constants).
            pub fn custom(path: impl Into<Cow<'static, str>>) -> Self {
                Self(path.into())
            }

            /// The underlying field path string.
            pub const fn as_str(&self) -> &str {
                match &self.0 {
                    Cow::Borrowed(s) => s,
                    Cow::Owned(s) => s.as_str(),
                }
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.0 == other
            }
        }

        impl PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.0 == *other
            }
        }
    };
}

macro_rules! define_scoped_read_mask {
    (
        $(#[$attr:meta])*
        pub struct $mask:ident from $field:ident default $default:expr;
    ) => {
        $(#[$attr])*
        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        pub struct $mask(Cow<'static, str>);

        impl $mask {
            /// The underlying comma-separated field mask string.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Default for $mask {
            fn default() -> Self {
                Self::from($default)
            }
        }

        impl AsRef<str> for $mask {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl From<$field> for $mask {
            fn from(field: $field) -> Self {
                Self(field.0)
            }
        }

        impl From<&'static str> for $mask {
            /// Escape hatch — build the mask from a raw comma-separated path
            /// string (e.g. one of the pre-computed
            /// [`read_masks`](crate::read_masks) constants). Prefer passing
            /// typed field constants when possible.
            fn from(s: &'static str) -> Self {
                Self(Cow::Borrowed(s))
            }
        }

        impl From<String> for $mask {
            /// Escape hatch — build the mask from a raw comma-separated path
            /// string. Prefer passing typed field constants when possible.
            fn from(s: String) -> Self {
                Self(Cow::Owned(s))
            }
        }

        impl From<&$field> for $mask {
            fn from(field: &$field) -> Self {
                Self(field.0.clone())
            }
        }

        impl From<&[$field]> for $mask {
            fn from(fields: &[$field]) -> Self {
                let joined = fields
                    .iter()
                    .map(|f| f.as_str())
                    .collect::<Vec<_>>()
                    .join(",");
                Self(Cow::Owned(field_mask_normalize(&joined)))
            }
        }

        impl<const N: usize> From<&[$field; N]> for $mask {
            fn from(fields: &[$field; N]) -> Self {
                Self::from(fields.as_slice())
            }
        }

        impl<const N: usize> From<[$field; N]> for $mask {
            fn from(fields: [$field; N]) -> Self {
                Self::from(fields.as_slice())
            }
        }

        impl From<Vec<$field>> for $mask {
            fn from(fields: Vec<$field>) -> Self {
                Self::from(fields.as_slice())
            }
        }

        impl From<$mask> for ::prost_types::FieldMask {
            fn from(mask: $mask) -> Self {
                use crate::field::FieldMaskUtil;
                ::prost_types::FieldMask::from_str(mask.as_str())
            }
        }

        // `IntoReadMask` impls are enumerated (instead of blanket-implemented
        // over `Into<$mask>`) so that an invalid argument has *no* candidate
        // impl, which lets the trait's `on_unimplemented` diagnostic fire.
        impl_into_read_mask!($mask: $mask, $field, &$field, &[$field], Vec<$field>, &'static str, String);

        impl<const N: usize> IntoReadMask<$mask> for [$field; N] {
            fn into_read_mask(self) -> $mask {
                self.into()
            }
        }

        impl<const N: usize> IntoReadMask<$mask> for &[$field; N] {
            fn into_read_mask(self) -> $mask {
                self.into()
            }
        }

        impl PartialEq<str> for $mask {
            fn eq(&self, other: &str) -> bool {
                self.0 == other
            }
        }

        impl PartialEq<&str> for $mask {
            fn eq(&self, other: &&str) -> bool {
                self.0 == *other
            }
        }
    };
}

macro_rules! impl_into_read_mask {
    ($mask:ident: $($ty:ty),* $(,)?) => {
        $(
            impl IntoReadMask<$mask> for $ty {
                fn into_read_mask(self) -> $mask {
                    self.into()
                }
            }
        )*
    };
}

// =============================================================================
// get_objects
// =============================================================================

define_field_paths! {
    /// Field paths for `get_objects`.
    pub struct ObjectField {
        /// Wildcard — request all object fields.
        ALL = "*",
        /// Object reference (object_id, version, digest).
        REFERENCE = "reference",
        /// The object ID.
        REFERENCE_OBJECT_ID = "reference.object_id",
        /// The object version.
        REFERENCE_VERSION = "reference.version",
        /// The object content digest.
        REFERENCE_DIGEST = "reference.digest",
        /// The full BCS-encoded object.
        BCS = "bcs",
    }
}

define_scoped_read_mask! {
    /// Scoped read mask for `get_objects` / `get_objects_with_versions`.
    pub struct ObjectReadMask from ObjectField default GET_OBJECTS_READ_MASK;
}

// =============================================================================
// list_owned_objects
// =============================================================================

define_field_paths! {
    /// Field paths for `list_owned_objects` and `get_coins`.
    pub struct OwnedObjectField {
        /// Wildcard — request all fields.
        ALL = "*",
        /// Object reference (object_id, version, digest).
        REFERENCE = "reference",
        /// The object ID.
        REFERENCE_OBJECT_ID = "reference.object_id",
        /// The object version.
        REFERENCE_VERSION = "reference.version",
        /// The object content digest.
        REFERENCE_DIGEST = "reference.digest",
        /// The Move type of the object.
        OBJECT_TYPE = "object_type",
        /// The object owner.
        OWNER = "owner",
        /// The full BCS-encoded object.
        BCS = "bcs",
    }
}

define_scoped_read_mask! {
    /// Scoped read mask for `list_owned_objects` and `get_coins`.
    pub struct OwnedObjectReadMask from OwnedObjectField default LIST_OWNED_OBJECTS_READ_MASK;
}

// =============================================================================
// get_transactions / execute_transaction
// =============================================================================

define_field_paths! {
    /// Field paths for `get_transactions` and `execute_transaction(s)`.
    pub struct TransactionField {
        /// Wildcard — request all fields.
        ALL = "*",
        /// Transaction data (all sub-fields).
        TRANSACTION = "transaction",
        /// The transaction digest.
        TRANSACTION_DIGEST = "transaction.digest",
        /// The full BCS-encoded transaction.
        TRANSACTION_BCS = "transaction.bcs",
        /// User signatures (all sub-fields).
        SIGNATURES = "signatures",
        /// The full BCS-encoded signatures.
        SIGNATURES_BCS = "signatures.bcs",
        /// Transaction effects (all sub-fields).
        EFFECTS = "effects",
        /// The effects digest.
        EFFECTS_DIGEST = "effects.digest",
        /// The full BCS-encoded effects.
        EFFECTS_BCS = "effects.bcs",
        /// Transaction events (all sub-fields).
        EVENTS = "events",
        /// The events digest.
        EVENTS_DIGEST = "events.digest",
        /// Individual events (all sub-fields).
        EVENTS_EVENTS = "events.events",
        /// Full BCS-encoded event.
        EVENTS_EVENTS_BCS = "events.events.bcs",
        /// The ID of the package that emitted the event.
        EVENTS_EVENTS_PACKAGE_ID = "events.events.package_id",
        /// The module that emitted the event.
        EVENTS_EVENTS_MODULE = "events.events.module",
        /// The sender that triggered the event.
        EVENTS_EVENTS_SENDER = "events.events.sender",
        /// The type of the event.
        EVENTS_EVENTS_EVENT_TYPE = "events.events.event_type",
        /// The full BCS-encoded contents of the event.
        EVENTS_EVENTS_BCS_CONTENTS = "events.events.bcs_contents",
        /// The JSON-encoded contents of the event.
        EVENTS_EVENTS_JSON_CONTENTS = "events.events.json_contents",
        /// Checkpoint sequence number that included the transaction.
        CHECKPOINT = "checkpoint",
        /// Timestamp of the checkpoint that included the transaction.
        TIMESTAMP = "timestamp",
        /// Input objects (all sub-fields).
        INPUT_OBJECTS = "input_objects",
        /// Input object reference (object_id, version, digest).
        INPUT_OBJECTS_REFERENCE = "input_objects.reference",
        /// Input object ID.
        INPUT_OBJECTS_REFERENCE_OBJECT_ID = "input_objects.reference.object_id",
        /// Input object version.
        INPUT_OBJECTS_REFERENCE_VERSION = "input_objects.reference.version",
        /// Input object digest.
        INPUT_OBJECTS_REFERENCE_DIGEST = "input_objects.reference.digest",
        /// The full BCS-encoded input object.
        INPUT_OBJECTS_BCS = "input_objects.bcs",
        /// Output objects (all sub-fields).
        OUTPUT_OBJECTS = "output_objects",
        /// Output object reference (object_id, version, digest).
        OUTPUT_OBJECTS_REFERENCE = "output_objects.reference",
        /// Output object ID.
        OUTPUT_OBJECTS_REFERENCE_OBJECT_ID = "output_objects.reference.object_id",
        /// Output object version.
        OUTPUT_OBJECTS_REFERENCE_VERSION = "output_objects.reference.version",
        /// Output object digest.
        OUTPUT_OBJECTS_REFERENCE_DIGEST = "output_objects.reference.digest",
        /// The full BCS-encoded output object.
        OUTPUT_OBJECTS_BCS = "output_objects.bcs",
        /// Balance changes (all sub-fields).
        BALANCE_CHANGES = "balance_changes",
        /// The owner whose balance changed.
        BALANCE_CHANGES_OWNER = "balance_changes.owner",
        /// The coin type of the balance change.
        BALANCE_CHANGES_COIN_TYPE = "balance_changes.coin_type",
        /// The signed amount of the balance change.
        BALANCE_CHANGES_AMOUNT = "balance_changes.amount",
        /// Object changes (all sub-fields).
        OBJECT_CHANGES = "object_changes",
        /// Published-package object changes.
        OBJECT_CHANGES_PUBLISHED = "object_changes.published",
        /// Mutated-object changes.
        OBJECT_CHANGES_MUTATED = "object_changes.mutated",
        /// Deleted-object changes.
        OBJECT_CHANGES_DELETED = "object_changes.deleted",
        /// Wrapped-object changes.
        OBJECT_CHANGES_WRAPPED = "object_changes.wrapped",
        /// Unwrapped-object changes.
        OBJECT_CHANGES_UNWRAPPED = "object_changes.unwrapped",
        /// Created-object changes.
        OBJECT_CHANGES_CREATED = "object_changes.created",
    }
}

define_scoped_read_mask! {
    /// Scoped read mask for `get_transactions` and `execute_transaction(s)`.
    pub struct TransactionReadMask from TransactionField default GET_TRANSACTIONS_READ_MASK;
}

// =============================================================================
// Checkpoint transactions (prefixed with "transactions.")
// =============================================================================

define_field_paths! {
    /// Field paths for executed transactions within checkpoint responses.
    ///
    /// All paths are prefixed with `transactions.`. Use these with
    /// [`CheckpointResponseReadMask`].
    pub struct CheckpointTransactionField {
        /// All transaction fields within the checkpoint.
        ALL = "transactions",
        /// Transaction data (all sub-fields).
        TRANSACTION = "transactions.transaction",
        /// The transaction digest.
        TRANSACTION_DIGEST = "transactions.transaction.digest",
        /// The full BCS-encoded transaction.
        TRANSACTION_BCS = "transactions.transaction.bcs",
        /// User signatures (all sub-fields).
        SIGNATURES = "transactions.signatures",
        /// The full BCS-encoded signatures.
        SIGNATURES_BCS = "transactions.signatures.bcs",
        /// Transaction effects (all sub-fields).
        EFFECTS = "transactions.effects",
        /// The effects digest.
        EFFECTS_DIGEST = "transactions.effects.digest",
        /// The full BCS-encoded effects.
        EFFECTS_BCS = "transactions.effects.bcs",
        /// Transaction events (all sub-fields).
        EVENTS = "transactions.events",
        /// The events digest.
        EVENTS_DIGEST = "transactions.events.digest",
        /// Checkpoint sequence number.
        CHECKPOINT = "transactions.checkpoint",
        /// Timestamp.
        TIMESTAMP = "transactions.timestamp",
        /// Input objects (all sub-fields).
        INPUT_OBJECTS = "transactions.input_objects",
        /// The full BCS-encoded input object.
        INPUT_OBJECTS_BCS = "transactions.input_objects.bcs",
        /// Output objects (all sub-fields).
        OUTPUT_OBJECTS = "transactions.output_objects",
        /// The full BCS-encoded output object.
        OUTPUT_OBJECTS_BCS = "transactions.output_objects.bcs",
        /// Balance changes (all sub-fields).
        BALANCE_CHANGES = "transactions.balance_changes",
        /// Object changes (all sub-fields).
        OBJECT_CHANGES = "transactions.object_changes",
    }
}

// =============================================================================
// Simulate executed transaction (prefixed with "executed_transaction.")
// =============================================================================

define_field_paths! {
    /// Field paths for the executed transaction within simulate responses.
    ///
    /// All paths are prefixed with `executed_transaction.`. Use these with
    /// [`SimulateReadMask`].
    pub struct SimulateExecutedTransactionField {
        /// All executed transaction fields.
        ALL = "executed_transaction",
        /// Transaction data (all sub-fields).
        TRANSACTION = "executed_transaction.transaction",
        /// The transaction digest.
        TRANSACTION_DIGEST = "executed_transaction.transaction.digest",
        /// The full BCS-encoded transaction.
        TRANSACTION_BCS = "executed_transaction.transaction.bcs",
        /// User signatures (all sub-fields).
        SIGNATURES = "executed_transaction.signatures",
        /// The full BCS-encoded signatures.
        SIGNATURES_BCS = "executed_transaction.signatures.bcs",
        /// Transaction effects (all sub-fields).
        EFFECTS = "executed_transaction.effects",
        /// The effects digest.
        EFFECTS_DIGEST = "executed_transaction.effects.digest",
        /// The full BCS-encoded effects.
        EFFECTS_BCS = "executed_transaction.effects.bcs",
        /// Transaction events (all sub-fields).
        EVENTS = "executed_transaction.events",
        /// The events digest.
        EVENTS_DIGEST = "executed_transaction.events.digest",
        /// Individual events — full BCS-encoded.
        EVENTS_EVENTS_BCS = "executed_transaction.events.events.bcs",
        /// Checkpoint sequence number.
        CHECKPOINT = "executed_transaction.checkpoint",
        /// Timestamp.
        TIMESTAMP = "executed_transaction.timestamp",
        /// Input objects (all sub-fields).
        INPUT_OBJECTS = "executed_transaction.input_objects",
        /// The full BCS-encoded input object.
        INPUT_OBJECTS_BCS = "executed_transaction.input_objects.bcs",
        /// Output objects (all sub-fields).
        OUTPUT_OBJECTS = "executed_transaction.output_objects",
        /// The full BCS-encoded output object.
        OUTPUT_OBJECTS_BCS = "executed_transaction.output_objects.bcs",
        /// Balance changes (all sub-fields).
        BALANCE_CHANGES = "executed_transaction.balance_changes",
        /// Object changes (all sub-fields).
        OBJECT_CHANGES = "executed_transaction.object_changes",
    }
}

// =============================================================================
// get_service_info
// =============================================================================

define_field_paths! {
    /// Field paths for `get_service_info`.
    pub struct ServiceInfoField {
        /// Wildcard — request all fields.
        ALL = "*",
        /// The chain ID (network identifier).
        CHAIN_ID = "chain_id",
        /// The chain identifier string.
        CHAIN = "chain",
        /// The current epoch.
        EPOCH = "epoch",
        /// Height of the last executed checkpoint.
        EXECUTED_CHECKPOINT_HEIGHT = "executed_checkpoint_height",
        /// Timestamp of the last executed checkpoint.
        EXECUTED_CHECKPOINT_TIMESTAMP = "executed_checkpoint_timestamp",
        /// Lowest available checkpoint for transaction/checkpoint data.
        LOWEST_AVAILABLE_CHECKPOINT = "lowest_available_checkpoint",
        /// Lowest available checkpoint for object data.
        LOWEST_AVAILABLE_CHECKPOINT_OBJECTS = "lowest_available_checkpoint_objects",
        /// The server version.
        SERVER = "server",
    }
}

define_scoped_read_mask! {
    /// Scoped read mask for `get_service_info`.
    pub struct ServiceInfoReadMask from ServiceInfoField default GET_SERVICE_INFO_READ_MASK;
}

// =============================================================================
// get_epoch
// =============================================================================

define_field_paths! {
    /// Field paths for `get_epoch`.
    ///
    /// Use [`EpochField::feature_flag`] and [`EpochField::attribute`] for
    /// individual protocol-config map entries.
    pub struct EpochField {
        /// Wildcard — request all fields.
        ALL = "*",
        /// The epoch number.
        EPOCH = "epoch",
        /// The validator committee for this epoch.
        COMMITTEE = "committee",
        /// The BCS-encoded system state.
        BCS_SYSTEM_STATE = "bcs_system_state",
        /// The first checkpoint in the epoch.
        FIRST_CHECKPOINT = "first_checkpoint",
        /// The last checkpoint in the epoch.
        LAST_CHECKPOINT = "last_checkpoint",
        /// The start timestamp of the epoch.
        START = "start",
        /// The end timestamp of the epoch.
        END = "end",
        /// The reference gas price during the epoch (in NANOS).
        REFERENCE_GAS_PRICE = "reference_gas_price",
        /// All protocol configuration fields.
        PROTOCOL_CONFIG = "protocol_config",
        /// The protocol version.
        PROTOCOL_CONFIG_PROTOCOL_VERSION = "protocol_config.protocol_version",
        /// All feature flags.
        PROTOCOL_CONFIG_FEATURE_FLAGS = "protocol_config.feature_flags",
        /// All protocol attributes.
        PROTOCOL_CONFIG_ATTRIBUTES = "protocol_config.attributes",
        /// All epoch-close-proof fields.
        EPOCH_CLOSE_PROOF = "epoch_close_proof",
        /// The certified checkpoint that closed the epoch.
        EPOCH_CLOSE_PROOF_CHECKPOINT = "epoch_close_proof.checkpoint",
        /// Effects of the epoch-change transaction.
        EPOCH_CLOSE_PROOF_END_OF_EPOCH_TRANSACTION_EFFECTS =
            "epoch_close_proof.end_of_epoch_transaction_effects",
        /// Events emitted by the epoch-change transaction.
        EPOCH_CLOSE_PROOF_END_OF_EPOCH_TRANSACTION_EVENTS =
            "epoch_close_proof.end_of_epoch_transaction_events",
        /// Raw BCS of the next epoch's start-of-epoch system-state objects.
        EPOCH_CLOSE_PROOF_BCS_NEXT_EPOCH_SYSTEM_STATE_OBJECTS =
            "epoch_close_proof.bcs_next_epoch_system_state_objects",
    }
}

impl EpochField {
    /// Field path for a specific feature flag by key.
    ///
    /// # Example
    ///
    /// ```
    /// use iota_sdk_grpc_types::read_mask_fields::EpochField;
    ///
    /// assert_eq!(
    ///     EpochField::feature_flag("enable_vdf").as_str(),
    ///     "protocol_config.feature_flags.enable_vdf",
    /// );
    /// ```
    pub fn feature_flag(key: &str) -> Self {
        Self::custom(format!("protocol_config.feature_flags.{key}"))
    }

    /// Field path for a specific protocol attribute by key.
    ///
    /// # Example
    ///
    /// ```
    /// use iota_sdk_grpc_types::read_mask_fields::EpochField;
    ///
    /// assert_eq!(
    ///     EpochField::attribute("max_tx_gas").as_str(),
    ///     "protocol_config.attributes.max_tx_gas",
    /// );
    /// ```
    pub fn attribute(key: &str) -> Self {
        Self::custom(format!("protocol_config.attributes.{key}"))
    }
}

define_scoped_read_mask! {
    /// Scoped read mask for `get_epoch`.
    pub struct EpochReadMask from EpochField default GET_EPOCH_READ_MASK;
}

// =============================================================================
// Checkpoint responses (get_checkpoint_*, stream_checkpoints*)
// =============================================================================

define_field_paths! {
    /// Field paths for checkpoint responses.
    pub struct CheckpointResponseField {
        /// Wildcard — request all fields.
        ALL = "*",
        /// All checkpoint data fields.
        CHECKPOINT = "checkpoint",
        /// The checkpoint sequence number.
        CHECKPOINT_SEQUENCE_NUMBER = "checkpoint.sequence_number",
        /// Checkpoint summary (all sub-fields).
        CHECKPOINT_SUMMARY = "checkpoint.summary",
        /// The checkpoint summary digest.
        CHECKPOINT_SUMMARY_DIGEST = "checkpoint.summary.digest",
        /// The full BCS-encoded checkpoint summary.
        CHECKPOINT_SUMMARY_BCS = "checkpoint.summary.bcs",
        /// Checkpoint contents (all sub-fields).
        CHECKPOINT_CONTENTS = "checkpoint.contents",
        /// The checkpoint contents digest.
        CHECKPOINT_CONTENTS_DIGEST = "checkpoint.contents.digest",
        /// The full BCS-encoded checkpoint contents.
        CHECKPOINT_CONTENTS_BCS = "checkpoint.contents.bcs",
        /// The validator aggregated signature.
        CHECKPOINT_SIGNATURE = "checkpoint.signature",
        /// All transactions in the checkpoint.
        TRANSACTIONS = "transactions",
        /// All events in the checkpoint.
        EVENTS = "events",
    }
}

define_scoped_read_mask! {
    /// Scoped read mask for checkpoint queries (`get_checkpoint_*`,
    /// `stream_checkpoints`, `stream_checkpoints_filtered`).
    pub struct CheckpointResponseReadMask from CheckpointResponseField default GET_CHECKPOINT_READ_MASK;
}

define_field_paths! {
    /// Field paths for checkpoint-level events.
    ///
    /// All paths are prefixed with `events.`. Use these with
    /// [`CheckpointResponseReadMask`].
    pub struct CheckpointEventField {
        /// All event fields.
        ALL = "events",
        /// Full BCS-encoded event.
        BCS = "events.bcs",
        /// The ID of the package that emitted the event.
        PACKAGE_ID = "events.package_id",
        /// The module that emitted the event.
        MODULE = "events.module",
        /// The sender that triggered the event.
        SENDER = "events.sender",
        /// The type of the event.
        EVENT_TYPE = "events.event_type",
        /// The full BCS-encoded contents of the event.
        BCS_CONTENTS = "events.bcs_contents",
        /// The JSON-encoded contents of the event.
        JSON_CONTENTS = "events.json_contents",
    }
}

// =============================================================================
// simulate_transaction
// =============================================================================

define_field_paths! {
    /// Field paths for `simulate_transaction(s)`.
    pub struct SimulateField {
        /// Wildcard — request all fields.
        ALL = "*",
        /// The simulated executed transaction (all sub-fields).
        EXECUTED_TRANSACTION = "executed_transaction",
        /// The suggested gas price (in NANOS).
        SUGGESTED_GAS_PRICE = "suggested_gas_price",
        /// Execution result (all sub-fields).
        EXECUTION_RESULT = "execution_result",
        /// Per-command results (on success, all sub-fields).
        EXECUTION_RESULT_COMMAND_RESULTS = "execution_result.command_results",
        /// Objects mutated by reference.
        EXECUTION_RESULT_COMMAND_RESULTS_MUTATED_BY_REF =
            "execution_result.command_results.mutated_by_ref",
        /// Return values from the command.
        EXECUTION_RESULT_COMMAND_RESULTS_RETURN_VALUES =
            "execution_result.command_results.return_values",
        /// Execution error details (on failure, all sub-fields).
        EXECUTION_RESULT_EXECUTION_ERROR = "execution_result.execution_error",
        /// The BCS-encoded error kind.
        EXECUTION_RESULT_EXECUTION_ERROR_BCS_KIND = "execution_result.execution_error.bcs_kind",
        /// The error source description.
        EXECUTION_RESULT_EXECUTION_ERROR_SOURCE = "execution_result.execution_error.source",
        /// The index of the command that failed.
        EXECUTION_RESULT_EXECUTION_ERROR_COMMAND_INDEX =
            "execution_result.execution_error.command_index",
    }
}

define_scoped_read_mask! {
    /// Scoped read mask for `simulate_transaction(s)`.
    pub struct SimulateReadMask from SimulateField default SIMULATE_TRANSACTIONS_READ_MASK;
}

// =============================================================================
// list_dynamic_fields
// =============================================================================

define_field_paths! {
    /// Field paths for `list_dynamic_fields`.
    pub struct DynamicFieldField {
        /// Wildcard — request all fields.
        ALL = "*",
        /// The kind of dynamic field (field or object).
        KIND = "kind",
        /// The parent object ID.
        PARENT = "parent",
        /// The field object ID.
        FIELD_ID = "field_id",
        /// The child object ID (for dynamic object fields).
        CHILD_ID = "child_id",
        /// BCS-encoded field name.
        NAME = "name",
        /// BCS-encoded field value.
        VALUE = "value",
        /// The Move type of the value.
        VALUE_TYPE = "value_type",
        /// The full field object (sub-fields match `get_objects`).
        FIELD_OBJECT = "field_object",
        /// The full child object (sub-fields match `get_objects`).
        CHILD_OBJECT = "child_object",
    }
}

define_scoped_read_mask! {
    /// Scoped read mask for `list_dynamic_fields`.
    pub struct DynamicFieldReadMask from DynamicFieldField default LIST_DYNAMIC_FIELDS_READ_MASK;
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

    #[test]
    fn field_paths_usable_in_consts() {
        // Field paths of different kinds can be collected into a single
        // constant by going through `as_str`.
        const PATHS: &[&str] = &[
            ObjectField::BCS.as_str(),
            TransactionField::EFFECTS_BCS.as_str(),
            CheckpointEventField::MODULE.as_str(),
        ];
        assert_eq!(PATHS, ["bcs", "effects.bcs", "events.module"]);
    }

    #[test]
    fn scoped_read_mask_from_single_field() {
        let mask: ObjectReadMask = ObjectField::BCS.into();
        assert_eq!(mask, "bcs");
    }

    #[test]
    fn scoped_read_mask_from_slice_normalizes() {
        // BCS subsumes nothing, REFERENCE subsumes REFERENCE_OBJECT_ID
        let mask: ObjectReadMask = [
            ObjectField::REFERENCE,
            ObjectField::REFERENCE_OBJECT_ID,
            ObjectField::BCS,
        ]
        .into();
        assert_eq!(mask, "bcs,reference");
    }

    #[test]
    fn scoped_read_mask_from_array_ref() {
        let fields = [ObjectField::REFERENCE, ObjectField::BCS];
        let mask: ObjectReadMask = (&fields).into();
        assert_eq!(mask, "bcs,reference");
    }
}
