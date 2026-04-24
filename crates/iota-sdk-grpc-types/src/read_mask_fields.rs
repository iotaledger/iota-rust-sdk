// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Type-safe read mask field selectors for gRPC endpoints.
//!
//! Each endpoint has a dedicated enum whose variants represent the fields
//! that the server can return. Pass one or more variants to
//! `ReadMask::from_fields` (in the `iota-sdk-grpc-client` crate) to build a
//! type-checked read mask.
//!
//! Every enum carries an `All` variant that acts as a wildcard — requesting
//! all fields at that level. Sub-fields are modelled with nested enums so
//! the hierarchy is visible through IDE autocompletion.
//!
//! # Example
//!
//! ```
//! use iota_sdk_grpc_types::read_mask_fields::{EffectsSubField, TransactionField};
//!
//! // Requesting effects (all sub-fields) + checkpoint number:
//! let fields = [
//!     TransactionField::Effects(EffectsSubField::All),
//!     TransactionField::Checkpoint,
//! ];
//! assert_eq!(fields[0].as_str(), "effects");
//! assert_eq!(fields[1].as_str(), "checkpoint");
//! ```

use std::fmt;

// =============================================================================
// Core trait
// =============================================================================

/// A field path that can be included in a gRPC read mask.
pub trait ReadMaskField {
    /// Returns the dot-delimited field path string.
    fn as_str(&self) -> &str;
}

// =============================================================================
// DynamicField — for map-key lookups (e.g. protocol_config.feature_flags.<key>)
// =============================================================================

/// A dynamically-constructed field path (for map-key lookups).
///
/// Created by helper methods such as [`EpochField::feature_flag`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DynamicField(String);

impl ReadMaskField for DynamicField {
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DynamicField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// =============================================================================
// Shared inner sub-enums
// =============================================================================

/// Sub-fields of an object reference.
///
/// Used by [`ObjectField`], [`OwnedObjectField`], and the `InputObjects` /
/// `OutputObjects` variants of executed-transaction enums.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ObjectReferenceField {
    /// All reference fields (object_id, version, digest).
    All,
    /// The object ID.
    ObjectId,
    /// The object version.
    Version,
    /// The object content digest.
    Digest,
}

/// Sub-fields of a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransactionSubField {
    /// All transaction fields (digest, bcs).
    All,
    /// The transaction digest.
    Digest,
    /// The full BCS-encoded transaction.
    Bcs,
}

/// Sub-fields of user signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignaturesSubField {
    /// All signature fields.
    All,
    /// The full BCS-encoded signature.
    Bcs,
}

/// Sub-fields of transaction effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EffectsSubField {
    /// All effects fields (digest, bcs).
    All,
    /// The effects digest.
    Digest,
    /// The full BCS-encoded effects.
    Bcs,
}

/// Fields of an individual event.
///
/// These are relative paths. The full path depends on context — the parent
/// enum adds the appropriate prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EventField {
    /// All event fields.
    All,
    /// Full BCS-encoded event (full deserialization).
    Bcs,
    /// The ID of the package that emitted the event.
    PackageId,
    /// The module that emitted the event.
    Module,
    /// The sender that triggered the event.
    Sender,
    /// The type of the event.
    EventType,
    /// The full BCS-encoded contents of the event.
    BcsContents,
    /// The JSON-encoded contents of the event.
    JsonContents,
}

/// Sub-fields of transaction events (the events collection on an executed
/// transaction).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransactionEventsSubField {
    /// All event fields (digest + all individual events).
    All,
    /// The events digest.
    Digest,
    /// Individual event fields.
    Events(EventField),
}

/// Sub-fields of an object (reference + bcs).
///
/// Used by `InputObjects` / `OutputObjects` variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ObjectSubField {
    /// All object fields (reference + bcs).
    All,
    /// Object reference sub-fields.
    Reference(ObjectReferenceField),
    /// The full BCS-encoded object.
    Bcs,
}

// =============================================================================
// Macro: generate ExecutedTransaction field enums with compile-time prefixes
// =============================================================================

/// Generates an executed-transaction field enum with a given path prefix.
///
/// This is invoked three times to produce `TransactionField` (no prefix),
/// `CheckpointTransactionField` (`transactions.` prefix), and
/// `SimulateExecutedTransactionField` (`executed_transaction.` prefix).
macro_rules! define_executed_transaction_fields {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident { prefix = $prefix:literal, all = $all:literal }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        $vis enum $name {
            /// Wildcard — request all fields at this level.
            All,
            /// Transaction data (digest, bcs).
            Transaction(TransactionSubField),
            /// User signatures.
            Signatures(SignaturesSubField),
            /// Transaction effects (digest, bcs).
            Effects(EffectsSubField),
            /// Transaction events.
            Events(TransactionEventsSubField),
            /// Checkpoint sequence number that included the transaction.
            Checkpoint,
            /// Timestamp of the checkpoint that included the transaction.
            Timestamp,
            /// Input objects of the transaction.
            InputObjects(ObjectSubField),
            /// Output objects of the transaction.
            OutputObjects(ObjectSubField),
        }

        impl $name {
            /// Returns the full field path string for this variant.
            pub fn as_str(&self) -> &'static str {
                match self {
                    Self::All => $all,

                    Self::Transaction(f) => match f {
                        TransactionSubField::All => concat!($prefix, "transaction"),
                        TransactionSubField::Digest => concat!($prefix, "transaction.digest"),
                        TransactionSubField::Bcs => concat!($prefix, "transaction.bcs"),
                    },

                    Self::Signatures(f) => match f {
                        SignaturesSubField::All => concat!($prefix, "signatures"),
                        SignaturesSubField::Bcs => concat!($prefix, "signatures.bcs"),
                    },

                    Self::Effects(f) => match f {
                        EffectsSubField::All => concat!($prefix, "effects"),
                        EffectsSubField::Digest => concat!($prefix, "effects.digest"),
                        EffectsSubField::Bcs => concat!($prefix, "effects.bcs"),
                    },

                    Self::Events(f) => match f {
                        TransactionEventsSubField::All => concat!($prefix, "events"),
                        TransactionEventsSubField::Digest => concat!($prefix, "events.digest"),
                        TransactionEventsSubField::Events(ef) => match ef {
                            EventField::All => concat!($prefix, "events.events"),
                            EventField::Bcs => concat!($prefix, "events.events.bcs"),
                            EventField::PackageId => concat!($prefix, "events.events.package_id"),
                            EventField::Module => concat!($prefix, "events.events.module"),
                            EventField::Sender => concat!($prefix, "events.events.sender"),
                            EventField::EventType => concat!($prefix, "events.events.event_type"),
                            EventField::BcsContents => concat!($prefix, "events.events.bcs_contents"),
                            EventField::JsonContents => concat!($prefix, "events.events.json_contents"),
                        },
                    },

                    Self::Checkpoint => concat!($prefix, "checkpoint"),
                    Self::Timestamp => concat!($prefix, "timestamp"),

                    Self::InputObjects(f) => match f {
                        ObjectSubField::All => concat!($prefix, "input_objects"),
                        ObjectSubField::Reference(rf) => match rf {
                            ObjectReferenceField::All => concat!($prefix, "input_objects.reference"),
                            ObjectReferenceField::ObjectId => concat!($prefix, "input_objects.reference.object_id"),
                            ObjectReferenceField::Version => concat!($prefix, "input_objects.reference.version"),
                            ObjectReferenceField::Digest => concat!($prefix, "input_objects.reference.digest"),
                        },
                        ObjectSubField::Bcs => concat!($prefix, "input_objects.bcs"),
                    },

                    Self::OutputObjects(f) => match f {
                        ObjectSubField::All => concat!($prefix, "output_objects"),
                        ObjectSubField::Reference(rf) => match rf {
                            ObjectReferenceField::All => concat!($prefix, "output_objects.reference"),
                            ObjectReferenceField::ObjectId => concat!($prefix, "output_objects.reference.object_id"),
                            ObjectReferenceField::Version => concat!($prefix, "output_objects.reference.version"),
                            ObjectReferenceField::Digest => concat!($prefix, "output_objects.reference.digest"),
                        },
                        ObjectSubField::Bcs => concat!($prefix, "output_objects.bcs"),
                    },
                }
            }
        }

        impl ReadMaskField for $name {
            fn as_str(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Three generated types for the three ExecutedTransaction contexts
// ---------------------------------------------------------------------------

define_executed_transaction_fields! {
    /// Read mask fields for `get_transactions` / `execute_transactions`.
    ///
    /// These produce **unprefixed** paths (e.g. `"effects.bcs"`).
    pub enum TransactionField { prefix = "", all = "*" }
}

define_executed_transaction_fields! {
    /// Read mask fields for executed transactions **within checkpoint
    /// responses**.
    ///
    /// All paths are prefixed with `transactions.` (e.g.
    /// `"transactions.effects.bcs"`).
    pub enum CheckpointTransactionField { prefix = "transactions.", all = "transactions" }
}

define_executed_transaction_fields! {
    /// Read mask fields for the executed transaction **within simulate
    /// responses**.
    ///
    /// All paths are prefixed with `executed_transaction.` (e.g.
    /// `"executed_transaction.effects.bcs"`).
    pub enum SimulateExecutedTransactionField { prefix = "executed_transaction.", all = "executed_transaction" }
}

// =============================================================================
// Per-endpoint top-level enums (hand-written)
// =============================================================================

// ── get_objects ──────────────────────────────────────────────────────────────

/// Read mask fields for `get_objects`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ObjectField {
    /// Wildcard — request all object fields.
    All,
    /// Object reference (object_id, version, digest).
    Reference(ObjectReferenceField),
    /// The full BCS-encoded object.
    Bcs,
}

impl ObjectField {
    /// Returns the full field path string for this variant.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::All => "*",
            Self::Reference(f) => match f {
                ObjectReferenceField::All => "reference",
                ObjectReferenceField::ObjectId => "reference.object_id",
                ObjectReferenceField::Version => "reference.version",
                ObjectReferenceField::Digest => "reference.digest",
            },
            Self::Bcs => "bcs",
        }
    }
}

impl ReadMaskField for ObjectField {
    fn as_str(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ObjectField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── list_owned_objects ──────────────────────────────────────────────────────

/// Read mask fields for `list_owned_objects`.
///
/// Extends [`ObjectField`] with `object_type` and `owner`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OwnedObjectField {
    /// Wildcard — request all fields.
    All,
    /// Object reference (object_id, version, digest).
    Reference(ObjectReferenceField),
    /// The Move type of the object.
    ObjectType,
    /// The object owner.
    Owner,
    /// The full BCS-encoded object.
    Bcs,
}

impl OwnedObjectField {
    /// Returns the full field path string for this variant.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::All => "*",
            Self::Reference(f) => match f {
                ObjectReferenceField::All => "reference",
                ObjectReferenceField::ObjectId => "reference.object_id",
                ObjectReferenceField::Version => "reference.version",
                ObjectReferenceField::Digest => "reference.digest",
            },
            Self::ObjectType => "object_type",
            Self::Owner => "owner",
            Self::Bcs => "bcs",
        }
    }
}

impl ReadMaskField for OwnedObjectField {
    fn as_str(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for OwnedObjectField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── get_service_info ────────────────────────────────────────────────────────

/// Read mask fields for `get_service_info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ServiceInfoField {
    /// Wildcard — request all fields.
    All,
    /// The chain ID (network identifier).
    ChainId,
    /// The chain identifier string.
    Chain,
    /// The current epoch.
    Epoch,
    /// Height of the last executed checkpoint.
    ExecutedCheckpointHeight,
    /// Timestamp of the last executed checkpoint.
    ExecutedCheckpointTimestamp,
    /// Lowest available checkpoint for transaction/checkpoint data.
    LowestAvailableCheckpoint,
    /// Lowest available checkpoint for object data.
    LowestAvailableCheckpointObjects,
    /// The server version.
    Server,
}

impl ServiceInfoField {
    /// Returns the full field path string for this variant.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::All => "*",
            Self::ChainId => "chain_id",
            Self::Chain => "chain",
            Self::Epoch => "epoch",
            Self::ExecutedCheckpointHeight => "executed_checkpoint_height",
            Self::ExecutedCheckpointTimestamp => "executed_checkpoint_timestamp",
            Self::LowestAvailableCheckpoint => "lowest_available_checkpoint",
            Self::LowestAvailableCheckpointObjects => "lowest_available_checkpoint_objects",
            Self::Server => "server",
        }
    }
}

impl ReadMaskField for ServiceInfoField {
    fn as_str(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ServiceInfoField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── get_epoch ───────────────────────────────────────────────────────────────

/// Sub-fields of the protocol configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProtocolConfigField {
    /// All protocol config fields.
    All,
    /// The protocol version.
    ProtocolVersion,
    /// All feature flags (map).
    FeatureFlags,
    /// A specific feature flag by key.
    ///
    /// Use [`ProtocolConfigField::feature_flag`] to construct.
    /// Produces `protocol_config.feature_flags.<key>`.
    FeatureFlag(String),
    /// All protocol attributes (map).
    Attributes,
    /// A specific protocol attribute by key.
    ///
    /// Use [`ProtocolConfigField::attribute`] to construct.
    /// Produces `protocol_config.attributes.<key>`.
    Attribute(String),
}

impl ProtocolConfigField {
    /// Returns the full field path string for this variant.
    pub fn as_str(&self) -> &str {
        match self {
            Self::All => "protocol_config",
            Self::ProtocolVersion => "protocol_config.protocol_version",
            Self::FeatureFlags => "protocol_config.feature_flags",
            Self::FeatureFlag(s) => s,
            Self::Attributes => "protocol_config.attributes",
            Self::Attribute(s) => s,
        }
    }

    /// Field path for a specific feature flag by key.
    ///
    /// # Example
    ///
    /// ```
    /// use iota_sdk_grpc_types::read_mask_fields::{ProtocolConfigField, ReadMaskField};
    ///
    /// let field = ProtocolConfigField::feature_flag("enable_vdf");
    /// assert_eq!(field.as_str(), "protocol_config.feature_flags.enable_vdf");
    /// ```
    pub fn feature_flag(key: &str) -> Self {
        Self::FeatureFlag(format!("protocol_config.feature_flags.{key}"))
    }

    /// Field path for a specific protocol attribute by key.
    ///
    /// # Example
    ///
    /// ```
    /// use iota_sdk_grpc_types::read_mask_fields::{ProtocolConfigField, ReadMaskField};
    ///
    /// let field = ProtocolConfigField::attribute("max_tx_gas");
    /// assert_eq!(field.as_str(), "protocol_config.attributes.max_tx_gas");
    /// ```
    pub fn attribute(key: &str) -> Self {
        Self::Attribute(format!("protocol_config.attributes.{key}"))
    }
}

impl ReadMaskField for ProtocolConfigField {
    fn as_str(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ProtocolConfigField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Read mask fields for `get_epoch`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EpochField {
    /// Wildcard — request all fields.
    All,
    /// The epoch number.
    Epoch,
    /// The validator committee for this epoch.
    Committee,
    /// The BCS-encoded system state.
    BcsSystemState,
    /// The first checkpoint in the epoch.
    FirstCheckpoint,
    /// The last checkpoint in the epoch.
    LastCheckpoint,
    /// The start timestamp of the epoch.
    Start,
    /// The end timestamp of the epoch.
    End,
    /// The reference gas price during the epoch (in NANOS).
    ReferenceGasPrice,
    /// Protocol configuration sub-fields.
    ProtocolConfig(ProtocolConfigField),
}

impl EpochField {
    /// Returns the full field path string for this variant.
    pub fn as_str(&self) -> &str {
        match self {
            Self::All => "*",
            Self::Epoch => "epoch",
            Self::Committee => "committee",
            Self::BcsSystemState => "bcs_system_state",
            Self::FirstCheckpoint => "first_checkpoint",
            Self::LastCheckpoint => "last_checkpoint",
            Self::Start => "start",
            Self::End => "end",
            Self::ReferenceGasPrice => "reference_gas_price",
            Self::ProtocolConfig(f) => f.as_str(),
        }
    }

    /// Field path for a specific feature flag by key.
    ///
    /// # Example
    ///
    /// ```
    /// use iota_sdk_grpc_types::read_mask_fields::{EpochField, ReadMaskField};
    ///
    /// let field = EpochField::feature_flag("enable_vdf");
    /// assert_eq!(field.as_str(), "protocol_config.feature_flags.enable_vdf");
    /// ```
    pub fn feature_flag(key: &str) -> Self {
        Self::ProtocolConfig(ProtocolConfigField::feature_flag(key))
    }

    /// Field path for a specific protocol attribute by key.
    ///
    /// # Example
    ///
    /// ```
    /// use iota_sdk_grpc_types::read_mask_fields::{EpochField, ReadMaskField};
    ///
    /// let field = EpochField::attribute("max_tx_gas");
    /// assert_eq!(field.as_str(), "protocol_config.attributes.max_tx_gas");
    /// ```
    pub fn attribute(key: &str) -> Self {
        Self::ProtocolConfig(ProtocolConfigField::attribute(key))
    }
}

impl ReadMaskField for EpochField {
    fn as_str(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for EpochField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── checkpoint queries ──────────────────────────────────────────────────────

/// Sub-fields of a checkpoint summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CheckpointSummaryField {
    /// All summary fields (digest, bcs).
    All,
    /// The checkpoint summary digest.
    Digest,
    /// The full BCS-encoded checkpoint summary.
    Bcs,
}

/// Sub-fields of checkpoint contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CheckpointContentsField {
    /// All contents fields (digest, bcs).
    All,
    /// The checkpoint contents digest.
    Digest,
    /// The full BCS-encoded checkpoint contents.
    Bcs,
}

/// Sub-fields of checkpoint data (summary, contents, signature).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CheckpointDataField {
    /// All checkpoint data fields.
    All,
    /// The checkpoint sequence number.
    SequenceNumber,
    /// Checkpoint summary sub-fields.
    Summary(CheckpointSummaryField),
    /// Checkpoint contents sub-fields.
    Contents(CheckpointContentsField),
    /// The validator aggregated signature.
    Signature,
}

impl CheckpointDataField {
    /// Returns the full field path string for this variant.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::All => "checkpoint",
            Self::SequenceNumber => "checkpoint.sequence_number",
            Self::Summary(f) => match f {
                CheckpointSummaryField::All => "checkpoint.summary",
                CheckpointSummaryField::Digest => "checkpoint.summary.digest",
                CheckpointSummaryField::Bcs => "checkpoint.summary.bcs",
            },
            Self::Contents(f) => match f {
                CheckpointContentsField::All => "checkpoint.contents",
                CheckpointContentsField::Digest => "checkpoint.contents.digest",
                CheckpointContentsField::Bcs => "checkpoint.contents.bcs",
            },
            Self::Signature => "checkpoint.signature",
        }
    }
}

impl ReadMaskField for CheckpointDataField {
    fn as_str(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for CheckpointDataField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Read mask fields for checkpoint endpoints (`get_checkpoint_*`,
/// `stream_checkpoints*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CheckpointResponseField {
    /// Wildcard — request all fields.
    All,
    /// Checkpoint data (summary, contents, signature).
    Checkpoint(CheckpointDataField),
    /// Executed transactions in the checkpoint.
    ///
    /// Uses `transactions.`-prefixed paths.
    Transactions(CheckpointTransactionField),
    /// Top-level checkpoint events (all events across all transactions).
    ///
    /// Uses `events.`-prefixed paths.
    Events(CheckpointEventField),
}

impl CheckpointResponseField {
    /// Returns the full field path string for this variant.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::All => "*",
            Self::Checkpoint(f) => f.as_str(),
            Self::Transactions(f) => f.as_str(),
            Self::Events(f) => f.as_str(),
        }
    }
}

impl ReadMaskField for CheckpointResponseField {
    fn as_str(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for CheckpointResponseField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Top-level event fields within a checkpoint response.
///
/// These are checkpoint-level events (flattened across all transactions),
/// prefixed with `events.`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CheckpointEventField {
    /// All event fields.
    All,
    /// Full BCS-encoded event.
    Bcs,
    /// The ID of the package that emitted the event.
    PackageId,
    /// The module that emitted the event.
    Module,
    /// The sender that triggered the event.
    Sender,
    /// The type of the event.
    EventType,
    /// The full BCS-encoded contents of the event.
    BcsContents,
    /// The JSON-encoded contents of the event.
    JsonContents,
}

impl CheckpointEventField {
    /// Returns the full field path string for this variant.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::All => "events",
            Self::Bcs => "events.bcs",
            Self::PackageId => "events.package_id",
            Self::Module => "events.module",
            Self::Sender => "events.sender",
            Self::EventType => "events.event_type",
            Self::BcsContents => "events.bcs_contents",
            Self::JsonContents => "events.json_contents",
        }
    }
}

impl ReadMaskField for CheckpointEventField {
    fn as_str(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for CheckpointEventField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── simulate_transactions ───────────────────────────────────────────────────

/// Sub-fields of command results (successful execution).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CommandResultsField {
    /// All command result fields.
    All,
    /// Objects mutated by reference.
    MutatedByRef,
    /// Return values from the command.
    ReturnValues,
}

/// Sub-fields of an execution error (failed execution).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ExecutionErrorField {
    /// All execution error fields.
    All,
    /// The BCS-encoded error kind.
    BcsKind,
    /// The error source description.
    Source,
    /// The index of the command that failed.
    CommandIndex,
}

/// Sub-fields of the execution result (oneof: command_results |
/// execution_error).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ExecutionResultField {
    /// All execution result fields.
    All,
    /// Per-command results (on success).
    CommandResults(CommandResultsField),
    /// Execution error details (on failure).
    ExecutionError(ExecutionErrorField),
}

impl ExecutionResultField {
    /// Returns the full field path string for this variant.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::All => "execution_result",
            Self::CommandResults(f) => match f {
                CommandResultsField::All => "execution_result.command_results",
                CommandResultsField::MutatedByRef => {
                    "execution_result.command_results.mutated_by_ref"
                }
                CommandResultsField::ReturnValues => {
                    "execution_result.command_results.return_values"
                }
            },
            Self::ExecutionError(f) => match f {
                ExecutionErrorField::All => "execution_result.execution_error",
                ExecutionErrorField::BcsKind => "execution_result.execution_error.bcs_kind",
                ExecutionErrorField::Source => "execution_result.execution_error.source",
                ExecutionErrorField::CommandIndex => {
                    "execution_result.execution_error.command_index"
                }
            },
        }
    }
}

impl ReadMaskField for ExecutionResultField {
    fn as_str(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ExecutionResultField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Read mask fields for `simulate_transactions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SimulateField {
    /// Wildcard — request all fields.
    All,
    /// The simulated executed transaction.
    ///
    /// Uses `executed_transaction.`-prefixed paths.
    ExecutedTransaction(SimulateExecutedTransactionField),
    /// The suggested gas price (in NANOS).
    SuggestedGasPrice,
    /// Execution result (command results on success, error on failure).
    ExecutionResult(ExecutionResultField),
}

impl SimulateField {
    /// Returns the full field path string for this variant.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::All => "*",
            Self::ExecutedTransaction(f) => f.as_str(),
            Self::SuggestedGasPrice => "suggested_gas_price",
            Self::ExecutionResult(f) => f.as_str(),
        }
    }
}

impl ReadMaskField for SimulateField {
    fn as_str(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for SimulateField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── list_dynamic_fields ─────────────────────────────────────────────────────

/// Read mask fields for `list_dynamic_fields`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DynamicFieldField {
    /// Wildcard — request all fields.
    All,
    /// The kind of dynamic field (field or object).
    Kind,
    /// The parent object ID.
    Parent,
    /// The field object ID.
    FieldId,
    /// The child object ID (for dynamic object fields).
    ChildId,
    /// BCS-encoded field name.
    Name,
    /// BCS-encoded field value.
    Value,
    /// The Move type of the value.
    ValueType,
    /// The full field object (sub-fields match `get_objects`).
    FieldObject,
    /// The full child object (sub-fields match `get_objects`).
    ChildObject,
}

impl DynamicFieldField {
    /// Returns the full field path string for this variant.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::All => "*",
            Self::Kind => "kind",
            Self::Parent => "parent",
            Self::FieldId => "field_id",
            Self::ChildId => "child_id",
            Self::Name => "name",
            Self::Value => "value",
            Self::ValueType => "value_type",
            Self::FieldObject => "field_object",
            Self::ChildObject => "child_object",
        }
    }
}

impl ReadMaskField for DynamicFieldField {
    fn as_str(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for DynamicFieldField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- TransactionField (unprefixed) --

    #[test]
    fn transaction_field_paths() {
        assert_eq!(TransactionField::All.as_str(), "*");
        assert_eq!(
            TransactionField::Transaction(TransactionSubField::All).as_str(),
            "transaction"
        );
        assert_eq!(
            TransactionField::Transaction(TransactionSubField::Digest).as_str(),
            "transaction.digest"
        );
        assert_eq!(
            TransactionField::Transaction(TransactionSubField::Bcs).as_str(),
            "transaction.bcs"
        );
        assert_eq!(
            TransactionField::Signatures(SignaturesSubField::All).as_str(),
            "signatures"
        );
        assert_eq!(
            TransactionField::Effects(EffectsSubField::All).as_str(),
            "effects"
        );
        assert_eq!(
            TransactionField::Effects(EffectsSubField::Digest).as_str(),
            "effects.digest"
        );
        assert_eq!(
            TransactionField::Effects(EffectsSubField::Bcs).as_str(),
            "effects.bcs"
        );
        assert_eq!(
            TransactionField::Events(TransactionEventsSubField::All).as_str(),
            "events"
        );
        assert_eq!(
            TransactionField::Events(TransactionEventsSubField::Events(EventField::PackageId))
                .as_str(),
            "events.events.package_id"
        );
        assert_eq!(TransactionField::Checkpoint.as_str(), "checkpoint");
        assert_eq!(TransactionField::Timestamp.as_str(), "timestamp");
        assert_eq!(
            TransactionField::InputObjects(ObjectSubField::All).as_str(),
            "input_objects"
        );
        assert_eq!(
            TransactionField::InputObjects(ObjectSubField::Reference(
                ObjectReferenceField::ObjectId
            ))
            .as_str(),
            "input_objects.reference.object_id"
        );
        assert_eq!(
            TransactionField::OutputObjects(ObjectSubField::Bcs).as_str(),
            "output_objects.bcs"
        );
    }

    // -- CheckpointTransactionField (transactions. prefix) --

    #[test]
    fn checkpoint_transaction_field_paths() {
        assert_eq!(CheckpointTransactionField::All.as_str(), "transactions");
        assert_eq!(
            CheckpointTransactionField::Transaction(TransactionSubField::Digest).as_str(),
            "transactions.transaction.digest"
        );
        assert_eq!(
            CheckpointTransactionField::Effects(EffectsSubField::Bcs).as_str(),
            "transactions.effects.bcs"
        );
        assert_eq!(
            CheckpointTransactionField::Events(TransactionEventsSubField::Events(
                EventField::Sender
            ))
            .as_str(),
            "transactions.events.events.sender"
        );
        assert_eq!(
            CheckpointTransactionField::InputObjects(ObjectSubField::Reference(
                ObjectReferenceField::Version
            ))
            .as_str(),
            "transactions.input_objects.reference.version"
        );
    }

    // -- SimulateExecutedTransactionField (executed_transaction. prefix) --

    #[test]
    fn simulate_executed_transaction_field_paths() {
        assert_eq!(
            SimulateExecutedTransactionField::All.as_str(),
            "executed_transaction"
        );
        assert_eq!(
            SimulateExecutedTransactionField::Effects(EffectsSubField::All).as_str(),
            "executed_transaction.effects"
        );
        assert_eq!(
            SimulateExecutedTransactionField::Transaction(TransactionSubField::Bcs).as_str(),
            "executed_transaction.transaction.bcs"
        );
    }

    // -- ObjectField --

    #[test]
    fn object_field_paths() {
        assert_eq!(ObjectField::All.as_str(), "*");
        assert_eq!(
            ObjectField::Reference(ObjectReferenceField::All).as_str(),
            "reference"
        );
        assert_eq!(
            ObjectField::Reference(ObjectReferenceField::ObjectId).as_str(),
            "reference.object_id"
        );
        assert_eq!(ObjectField::Bcs.as_str(), "bcs");
    }

    // -- OwnedObjectField --

    #[test]
    fn owned_object_field_paths() {
        assert_eq!(OwnedObjectField::All.as_str(), "*");
        assert_eq!(OwnedObjectField::ObjectType.as_str(), "object_type");
        assert_eq!(OwnedObjectField::Owner.as_str(), "owner");
        assert_eq!(
            OwnedObjectField::Reference(ObjectReferenceField::Digest).as_str(),
            "reference.digest"
        );
    }

    // -- ServiceInfoField --

    #[test]
    fn service_info_field_paths() {
        assert_eq!(ServiceInfoField::All.as_str(), "*");
        assert_eq!(ServiceInfoField::ChainId.as_str(), "chain_id");
        assert_eq!(ServiceInfoField::Chain.as_str(), "chain");
        assert_eq!(ServiceInfoField::Epoch.as_str(), "epoch");
        assert_eq!(ServiceInfoField::Server.as_str(), "server");
    }

    // -- EpochField --

    #[test]
    fn epoch_field_paths() {
        assert_eq!(EpochField::All.as_str(), "*");
        assert_eq!(EpochField::Epoch.as_str(), "epoch");
        assert_eq!(
            EpochField::ReferenceGasPrice.as_str(),
            "reference_gas_price"
        );
        assert_eq!(
            EpochField::ProtocolConfig(ProtocolConfigField::All).as_str(),
            "protocol_config"
        );
        assert_eq!(
            EpochField::ProtocolConfig(ProtocolConfigField::ProtocolVersion).as_str(),
            "protocol_config.protocol_version"
        );
        assert_eq!(
            EpochField::ProtocolConfig(ProtocolConfigField::FeatureFlags).as_str(),
            "protocol_config.feature_flags"
        );
    }

    #[test]
    fn epoch_keyed_field_paths() {
        let flag = EpochField::feature_flag("enable_vdf");
        assert_eq!(flag.as_str(), "protocol_config.feature_flags.enable_vdf");

        let attr = EpochField::attribute("max_tx_gas");
        assert_eq!(attr.as_str(), "protocol_config.attributes.max_tx_gas");
    }

    #[test]
    fn protocol_config_keyed_field_paths() {
        let flag = ProtocolConfigField::feature_flag("enable_vdf");
        assert_eq!(flag.as_str(), "protocol_config.feature_flags.enable_vdf");

        let attr = ProtocolConfigField::attribute("max_tx_gas");
        assert_eq!(attr.as_str(), "protocol_config.attributes.max_tx_gas");
    }

    // -- CheckpointResponseField --

    #[test]
    fn checkpoint_response_field_paths() {
        assert_eq!(CheckpointResponseField::All.as_str(), "*");
        assert_eq!(
            CheckpointResponseField::Checkpoint(CheckpointDataField::All).as_str(),
            "checkpoint"
        );
        assert_eq!(
            CheckpointResponseField::Checkpoint(CheckpointDataField::Summary(
                CheckpointSummaryField::Bcs
            ))
            .as_str(),
            "checkpoint.summary.bcs"
        );
        assert_eq!(
            CheckpointResponseField::Checkpoint(CheckpointDataField::Signature).as_str(),
            "checkpoint.signature"
        );
        assert_eq!(
            CheckpointResponseField::Transactions(CheckpointTransactionField::Effects(
                EffectsSubField::Bcs
            ))
            .as_str(),
            "transactions.effects.bcs"
        );
        assert_eq!(
            CheckpointResponseField::Events(CheckpointEventField::PackageId).as_str(),
            "events.package_id"
        );
    }

    // -- SimulateField --

    #[test]
    fn simulate_field_paths() {
        assert_eq!(SimulateField::All.as_str(), "*");
        assert_eq!(
            SimulateField::SuggestedGasPrice.as_str(),
            "suggested_gas_price"
        );
        assert_eq!(
            SimulateField::ExecutedTransaction(SimulateExecutedTransactionField::Effects(
                EffectsSubField::All
            ))
            .as_str(),
            "executed_transaction.effects"
        );
        assert_eq!(
            SimulateField::ExecutionResult(ExecutionResultField::All).as_str(),
            "execution_result"
        );
        assert_eq!(
            SimulateField::ExecutionResult(ExecutionResultField::ExecutionError(
                ExecutionErrorField::BcsKind
            ))
            .as_str(),
            "execution_result.execution_error.bcs_kind"
        );
        assert_eq!(
            SimulateField::ExecutionResult(ExecutionResultField::CommandResults(
                CommandResultsField::ReturnValues
            ))
            .as_str(),
            "execution_result.command_results.return_values"
        );
    }

    // -- DynamicFieldField --

    #[test]
    fn dynamic_field_field_paths() {
        assert_eq!(DynamicFieldField::All.as_str(), "*");
        assert_eq!(DynamicFieldField::Kind.as_str(), "kind");
        assert_eq!(DynamicFieldField::Parent.as_str(), "parent");
        assert_eq!(DynamicFieldField::FieldId.as_str(), "field_id");
        assert_eq!(DynamicFieldField::ChildId.as_str(), "child_id");
        assert_eq!(DynamicFieldField::Name.as_str(), "name");
        assert_eq!(DynamicFieldField::Value.as_str(), "value");
        assert_eq!(DynamicFieldField::ValueType.as_str(), "value_type");
        assert_eq!(DynamicFieldField::FieldObject.as_str(), "field_object");
        assert_eq!(DynamicFieldField::ChildObject.as_str(), "child_object");
    }

    // -- ReadMaskField trait --

    #[test]
    fn read_mask_field_trait() {
        // Verify the trait works with different types
        fn check(f: &dyn ReadMaskField, expected: &str) {
            assert_eq!(f.as_str(), expected);
        }
        check(&TransactionField::Checkpoint, "checkpoint");
        check(&ObjectField::Bcs, "bcs");
        check(&DynamicField("custom.path".to_string()), "custom.path");
    }
}
