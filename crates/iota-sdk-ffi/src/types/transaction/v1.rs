// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{fmt, sync::Arc};

use iota_types::{GasCostSummary, IdOperation};

use crate::types::{
    digest::Digest,
    execution_status::ExecutionStatus,
    object::{ObjectId, Owner},
};

/// Version 1 of TransactionEffects
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// effects-v1 = execution-status
///              u64                                ; epoch
///              gas-cost-summary
///              digest                             ; transaction digest
///              (option u32)                       ; gas object index
///              (option digest)                    ; events digest
///              (vector digest)                    ; list of transaction dependencies
///              u64                                ; lamport version
///              (vector changed-object)
///              (vector unchanged-shared-object)
///              (option digest)                    ; auxiliary data digest
/// ```
#[derive(uniffi::Record)]
#[uniffi::export(Display)]
pub struct TransactionEffectsV1 {
    /// The status of the execution
    pub status: ExecutionStatus,
    /// The epoch when this transaction was executed.
    pub epoch: u64,
    /// The gas used by this transaction
    pub gas_used: GasCostSummary,
    /// The transaction digest
    pub transaction_digest: Arc<Digest>,
    /// The updated gas object reference, as an index into the `changed_objects`
    /// vector. Having a dedicated field for convenient access.
    /// System transaction that don't require gas will leave this as None.
    #[uniffi(default = None)]
    pub gas_object_index: Option<u32>,
    /// The digest of the events emitted during execution,
    /// can be None if the transaction does not emit any event.
    #[uniffi(default = None)]
    pub events_digest: Option<Arc<Digest>>,
    /// The set of transaction digests this transaction depends on.
    pub dependencies: Vec<Arc<Digest>>,
    /// The version number of all the written Move objects by this transaction.
    pub lamport_version: u64,
    /// Objects whose state are changed in the object store.
    pub changed_objects: Vec<ChangedObject>,
    /// Shared objects that are not mutated in this transaction. Unlike owned
    /// objects, read-only shared objects' version are not committed in the
    /// transaction, and in order for a node to catch up and execute it
    /// without consensus sequencing, the version needs to be committed in
    /// the effects.
    pub unchanged_shared_objects: Vec<UnchangedSharedObject>,
    /// Auxiliary data that are not protocol-critical, generated as part of the
    /// effects but are stored separately. Storing it separately allows us
    /// to avoid bloating the effects with data that are not critical.
    /// It also provides more flexibility on the format and type of the data.
    #[uniffi(default = None)]
    pub auxiliary_data_digest: Option<Arc<Digest>>,
}

impl fmt::Display for TransactionEffectsV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Helper to format optional digest
        let fmt_opt_digest = |d: &Option<Arc<Digest>>| -> String {
            d.as_ref()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string())
        };
        let dependencies = if self.dependencies.is_empty() {
            String::from("[]")
        } else {
            format!(
                "[{}]",
                self.dependencies
                    .iter()
                    .map(|d| d.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        let changed = if self.changed_objects.is_empty() {
            String::from("[]")
        } else {
            format!(
                "[{}]",
                self.changed_objects
                    .iter()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        let unchanged = if self.unchanged_shared_objects.is_empty() {
            String::from("[]")
        } else {
            format!(
                "[{}]",
                self.unchanged_shared_objects
                    .iter()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        write!(
            f,
            "TransactionEffectsV1(status={}, epoch={}, gas_used={}, tx_digest={}, gas_object_index={:?}, events_digest={}, dependencies={}, lamport_version={}, changed_objects={}, unchanged_shared_objects={}, auxiliary_data_digest={})",
            self.status,
            self.epoch,
            self.gas_used,
            self.transaction_digest,
            self.gas_object_index,
            fmt_opt_digest(&self.events_digest),
            dependencies,
            self.lamport_version,
            changed,
            unchanged,
            fmt_opt_digest(&self.auxiliary_data_digest)
        )
    }
}

impl From<iota_types::TransactionEffectsV1> for TransactionEffectsV1 {
    fn from(value: iota_types::TransactionEffectsV1) -> Self {
        Self {
            status: value.status.into(),
            epoch: value.epoch,
            gas_used: value.gas_used,
            transaction_digest: Arc::new(value.transaction_digest.into()),
            gas_object_index: value.gas_object_index,
            events_digest: value.events_digest.map(Into::into).map(Arc::new),
            dependencies: value
                .dependencies
                .into_iter()
                .map(Into::into)
                .map(Arc::new)
                .collect(),
            lamport_version: value.lamport_version,
            changed_objects: value.changed_objects.into_iter().map(Into::into).collect(),
            unchanged_shared_objects: value
                .unchanged_shared_objects
                .into_iter()
                .map(Into::into)
                .collect(),
            auxiliary_data_digest: value.auxiliary_data_digest.map(Into::into).map(Arc::new),
        }
    }
}

impl From<TransactionEffectsV1> for iota_types::TransactionEffectsV1 {
    fn from(value: TransactionEffectsV1) -> Self {
        Self {
            status: value.status.into(),
            epoch: value.epoch,
            gas_used: value.gas_used,
            transaction_digest: **value.transaction_digest,
            gas_object_index: value.gas_object_index,
            events_digest: value.events_digest.map(|v| **v),
            dependencies: value.dependencies.into_iter().map(|v| **v).collect(),
            lamport_version: value.lamport_version,
            changed_objects: value.changed_objects.into_iter().map(Into::into).collect(),
            unchanged_shared_objects: value
                .unchanged_shared_objects
                .into_iter()
                .map(Into::into)
                .collect(),
            auxiliary_data_digest: value.auxiliary_data_digest.map(|v| **v),
        }
    }
}

/// Input/output state of an object that was changed during execution
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// changed-object = object-id object-in object-out id-operation
/// ```
#[derive(Debug, uniffi::Record)]
#[uniffi::export(Display)]
pub struct ChangedObject {
    /// Id of the object
    pub object_id: Arc<ObjectId>,
    /// State of the object in the store prior to this transaction.
    pub input_state: ObjectIn,
    /// State of the object in the store after this transaction.
    pub output_state: ObjectOut,
    /// Whether this object ID is created or deleted in this transaction.
    /// This information isn't required by the protocol but is useful for
    /// providing more detailed semantics on object changes.
    pub id_operation: IdOperation,
}

impl fmt::Display for ChangedObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChangedObject(object_id={})", self.object_id)
    }
}

impl From<iota_types::ChangedObject> for ChangedObject {
    fn from(value: iota_types::ChangedObject) -> Self {
        Self {
            object_id: Arc::new(value.object_id.into()),
            input_state: value.input_state.into(),
            output_state: value.output_state.into(),
            id_operation: value.id_operation,
        }
    }
}

impl From<ChangedObject> for iota_types::ChangedObject {
    fn from(value: ChangedObject) -> Self {
        Self {
            object_id: **value.object_id,
            input_state: value.input_state.into(),
            output_state: value.output_state.into(),
            id_operation: value.id_operation,
        }
    }
}

/// A shared object that wasn't changed during execution
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// unchanged-shared-object = object-id unchanged-shared-object-kind
/// ```
#[derive(Debug, uniffi::Record)]
#[uniffi::export(Display)]
pub struct UnchangedSharedObject {
    pub object_id: Arc<ObjectId>,
    pub kind: UnchangedSharedKind,
}

impl fmt::Display for UnchangedSharedObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UnchangedSharedObject(object_id={}, kind={})",
            self.object_id, self.kind
        )
    }
}

impl From<iota_types::UnchangedSharedObject> for UnchangedSharedObject {
    fn from(value: iota_types::UnchangedSharedObject) -> Self {
        Self {
            object_id: Arc::new(value.object_id.into()),
            kind: value.kind.into(),
        }
    }
}

impl From<UnchangedSharedObject> for iota_types::UnchangedSharedObject {
    fn from(value: UnchangedSharedObject) -> Self {
        Self {
            object_id: **value.object_id,
            kind: value.kind.into(),
        }
    }
}

/// Type of unchanged shared object
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// unchanged-shared-object-kind =  read-only-root
///                              =/ mutate-deleted
///                              =/ read-deleted
///                              =/ cancelled
///                              =/ per-epoch-config
///
/// read-only-root      = %x00 u64 digest
/// mutate-deleted      = %x01 u64
/// read-deleted        = %x02 u64
/// cancelled           = %x03 u64
/// per-epoch-config    = %x04
/// ```
#[derive(Debug, uniffi::Enum)]
pub enum UnchangedSharedKind {
    /// Read-only shared objects from the input. We don't really need
    /// ObjectDigest for protocol correctness, but it will make it easier to
    /// verify untrusted read.
    ReadOnlyRoot { version: u64, digest: Arc<Digest> },
    /// Deleted shared objects that appear mutably/owned in the input.
    MutateDeleted { version: u64 },
    /// Deleted shared objects that appear as read-only in the input.
    ReadDeleted { version: u64 },
    /// Shared objects in cancelled transaction. The sequence number embed
    /// cancellation reason.
    Cancelled { version: u64 },
    /// Read of a per-epoch config object that should remain the same during an
    /// epoch.
    PerEpochConfig,
}

impl From<iota_types::UnchangedSharedKind> for UnchangedSharedKind {
    fn from(value: iota_types::UnchangedSharedKind) -> Self {
        match value {
            iota_types::UnchangedSharedKind::ReadOnlyRoot { version, digest } => {
                Self::ReadOnlyRoot {
                    version,
                    digest: Arc::new(digest.into()),
                }
            }
            iota_types::UnchangedSharedKind::MutateDeleted { version } => {
                Self::MutateDeleted { version }
            }
            iota_types::UnchangedSharedKind::ReadDeleted { version } => {
                Self::ReadDeleted { version }
            }
            iota_types::UnchangedSharedKind::Cancelled { version } => Self::Cancelled { version },
            iota_types::UnchangedSharedKind::PerEpochConfig => Self::PerEpochConfig,
        }
    }
}

impl From<UnchangedSharedKind> for iota_types::UnchangedSharedKind {
    fn from(value: UnchangedSharedKind) -> Self {
        match value {
            UnchangedSharedKind::ReadOnlyRoot { version, digest } => Self::ReadOnlyRoot {
                version,
                digest: **digest,
            },
            UnchangedSharedKind::MutateDeleted { version } => Self::MutateDeleted { version },
            UnchangedSharedKind::ReadDeleted { version } => Self::ReadDeleted { version },
            UnchangedSharedKind::Cancelled { version } => Self::Cancelled { version },
            UnchangedSharedKind::PerEpochConfig => Self::PerEpochConfig,
        }
    }
}

/// State of an object prior to execution
///
/// If an object exists (at root-level) in the store prior to this transaction,
/// it should be Data, otherwise it's Missing, e.g. wrapped objects should be
/// Missing.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// object-in = object-in-missing / object-in-data
///
/// object-in-missing = %x00
/// object-in-data    = %x01 u64 digest owner
/// ```
#[derive(Debug, uniffi::Enum)]
pub enum ObjectIn {
    Missing,
    /// The old version, digest and owner.
    Data {
        version: u64,
        digest: Arc<Digest>,
        owner: Arc<Owner>,
    },
}

impl From<iota_types::ObjectIn> for ObjectIn {
    fn from(value: iota_types::ObjectIn) -> Self {
        match value {
            iota_types::ObjectIn::Missing => Self::Missing,
            iota_types::ObjectIn::Data {
                version,
                digest,
                owner,
            } => Self::Data {
                version,
                digest: Arc::new(digest.into()),
                owner: Arc::new(owner.into()),
            },
        }
    }
}

impl From<ObjectIn> for iota_types::ObjectIn {
    fn from(value: ObjectIn) -> Self {
        match value {
            ObjectIn::Missing => Self::Missing,
            ObjectIn::Data {
                version,
                digest,
                owner,
            } => Self::Data {
                version,
                digest: **digest,
                owner: **owner,
            },
        }
    }
}

/// State of an object after execution
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// object-out  =  object-out-missing
///             =/ object-out-object-write
///             =/ object-out-package-write
///
///
/// object-out-missing        = %x00
/// object-out-object-write   = %x01 digest owner
/// object-out-package-write  = %x02 version digest
/// ```
#[derive(Debug, uniffi::Enum)]
pub enum ObjectOut {
    /// Same definition as in ObjectIn.
    Missing,
    /// Any written object, including all of mutated, created, unwrapped today.
    ObjectWrite {
        digest: Arc<Digest>,
        owner: Arc<Owner>,
    },
    /// Packages writes need to be tracked separately with version because
    /// we don't use lamport version for package publish and upgrades.
    PackageWrite { version: u64, digest: Arc<Digest> },
}

impl From<iota_types::ObjectOut> for ObjectOut {
    fn from(value: iota_types::ObjectOut) -> Self {
        match value {
            iota_types::ObjectOut::Missing => Self::Missing,
            iota_types::ObjectOut::ObjectWrite { digest, owner } => Self::ObjectWrite {
                digest: Arc::new(digest.into()),
                owner: Arc::new(owner.into()),
            },
            iota_types::ObjectOut::PackageWrite { version, digest } => Self::PackageWrite {
                version,
                digest: Arc::new(digest.into()),
            },
        }
    }
}

// Display impls for enums (placed after their definitions)
impl fmt::Display for UnchangedSharedKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnchangedSharedKind::ReadOnlyRoot { version, digest } => {
                write!(f, "ReadOnlyRoot(version={}, digest={})", version, digest)
            }
            UnchangedSharedKind::MutateDeleted { version } => {
                write!(f, "MutateDeleted(version={})", version)
            }
            UnchangedSharedKind::ReadDeleted { version } => {
                write!(f, "ReadDeleted(version={})", version)
            }
            UnchangedSharedKind::Cancelled { version } => {
                write!(f, "Cancelled(version={})", version)
            }
            UnchangedSharedKind::PerEpochConfig => write!(f, "PerEpochConfig"),
        }
    }
}

impl From<ObjectOut> for iota_types::ObjectOut {
    fn from(value: ObjectOut) -> Self {
        match value {
            ObjectOut::Missing => Self::Missing,
            ObjectOut::ObjectWrite { digest, owner } => Self::ObjectWrite {
                digest: **digest,
                owner: **owner,
            },
            ObjectOut::PackageWrite { version, digest } => Self::PackageWrite {
                version,
                digest: **digest,
            },
        }
    }
}

impl fmt::Display for ObjectIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObjectIn::Missing => write!(f, "Missing"),
            ObjectIn::Data {
                version,
                digest,
                owner: _,
            } => {
                write!(f, "Data(version={}, digest={})", version, digest)
            }
        }
    }
}

impl fmt::Display for ObjectOut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObjectOut::Missing => write!(f, "Missing"),
            ObjectOut::ObjectWrite { digest, owner: _ } => {
                write!(f, "ObjectWrite(digest={})", digest)
            }
            ObjectOut::PackageWrite { version, digest } => {
                write!(f, "PackageWrite(version={}, digest={})", version, digest)
            }
        }
    }
}

/// Defines what happened to an ObjectId during execution
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// id-operation =  id-operation-none
///              =/ id-operation-created
///              =/ id-operation-deleted
///
/// id-operation-none       = %x00
/// id-operation-created    = %x01
/// id-operation-deleted    = %x02
/// ```
#[uniffi::remote(Enum)]
pub enum IdOperation {
    None,
    Created,
    Deleted,
}
