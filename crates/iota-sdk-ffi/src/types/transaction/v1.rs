// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_sdk::types::{GasCostSummary, IdOperation};

use crate::types::{
    digest::{EffectsAuxDataDigest, ObjectDigest, TransactionDigest, TransactionEventsDigest},
    execution_status::ExecutionStatus,
    object::{ObjectId, Owner},
    version::Version,
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
pub struct TransactionEffectsV1 {
    /// The status of the execution
    pub status: ExecutionStatus,
    /// The epoch when this transaction was executed.
    pub epoch: u64,
    /// The gas used by this transaction
    pub gas_cost_summary: GasCostSummary,
    /// The transaction digest
    pub transaction_digest: Arc<TransactionDigest>,
    /// The updated gas object reference, as an index into the `changed_objects`
    /// vector. Having a dedicated field for convenient access.
    /// System transaction that don't require gas will leave this as None.
    #[uniffi(default = None)]
    pub gas_object_index: Option<u32>,
    /// The digest of the events emitted during execution,
    /// can be None if the transaction does not emit any event.
    #[uniffi(default = None)]
    pub events_digest: Option<Arc<TransactionEventsDigest>>,
    /// The set of transaction digests this transaction depends on.
    pub dependencies: Vec<Arc<TransactionDigest>>,
    /// The version number of all the written Move objects by this transaction.
    pub lamport_version: Arc<Version>,
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
    pub auxiliary_data_digest: Option<Arc<EffectsAuxDataDigest>>,
}

impl From<iota_sdk::types::TransactionEffectsV1> for TransactionEffectsV1 {
    fn from(value: iota_sdk::types::TransactionEffectsV1) -> Self {
        Self {
            status: value.status.into(),
            epoch: value.epoch,
            gas_cost_summary: value.gas_cost_summary,
            transaction_digest: Arc::new(value.transaction_digest.into()),
            gas_object_index: value.gas_object_index,
            events_digest: value.events_digest.map(Into::into).map(Arc::new),
            dependencies: value
                .dependencies
                .into_iter()
                .map(Into::into)
                .map(Arc::new)
                .collect(),
            lamport_version: Arc::new(value.lamport_version.into()),
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

impl From<TransactionEffectsV1> for iota_sdk::types::TransactionEffectsV1 {
    fn from(value: TransactionEffectsV1) -> Self {
        Self {
            status: value.status.into(),
            epoch: value.epoch,
            gas_cost_summary: value.gas_cost_summary,
            transaction_digest: **value.transaction_digest,
            gas_object_index: value.gas_object_index,
            events_digest: value.events_digest.map(|v| **v),
            dependencies: value.dependencies.into_iter().map(|v| **v).collect(),
            lamport_version: **value.lamport_version,
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
#[derive(uniffi::Record)]
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

impl From<iota_sdk::types::ChangedObject> for ChangedObject {
    fn from(value: iota_sdk::types::ChangedObject) -> Self {
        Self {
            object_id: Arc::new(value.object_id.into()),
            input_state: value.input_state.into(),
            output_state: value.output_state.into(),
            id_operation: value.id_operation,
        }
    }
}

impl From<ChangedObject> for iota_sdk::types::ChangedObject {
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
#[derive(uniffi::Record)]
pub struct UnchangedSharedObject {
    pub object_id: Arc<ObjectId>,
    pub kind: UnchangedSharedKind,
}

impl From<iota_sdk::types::UnchangedSharedObject> for UnchangedSharedObject {
    fn from(value: iota_sdk::types::UnchangedSharedObject) -> Self {
        Self {
            object_id: Arc::new(value.object_id.into()),
            kind: value.kind.into(),
        }
    }
}

impl From<UnchangedSharedObject> for iota_sdk::types::UnchangedSharedObject {
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
///                              =/ canceled
///                              =/ per-epoch-config
///
/// read-only-root      = %d00 u64 digest
/// mutate-deleted      = %d01 u64
/// read-deleted        = %d02 u64
/// canceled           = %d03 u64
/// per-epoch-config    = %d04
/// ```
#[derive(uniffi::Enum)]
pub enum UnchangedSharedKind {
    /// Read-only shared objects from the input. We don't really need
    /// ObjectDigest for protocol correctness, but it will make it easier to
    /// verify untrusted read.
    ReadOnlyRoot {
        version: Arc<Version>,
        digest: Arc<ObjectDigest>,
    },
    /// Deleted shared objects that appear mutably/owned in the input.
    MutateDeleted { version: Arc<Version> },
    /// Deleted shared objects that appear as read-only in the input.
    ReadDeleted { version: Arc<Version> },
    /// Shared objects in canceled transaction. The sequence number embed
    /// cancellation reason.
    Canceled { version: Arc<Version> },
    /// Read of a per-epoch config object that should remain the same during an
    /// epoch.
    PerEpochConfig,
}

impl From<iota_sdk::types::UnchangedSharedKind> for UnchangedSharedKind {
    fn from(value: iota_sdk::types::UnchangedSharedKind) -> Self {
        match value {
            iota_sdk::types::UnchangedSharedKind::ReadOnlyRoot { version, digest } => {
                Self::ReadOnlyRoot {
                    version: Arc::new(version.into()),
                    digest: Arc::new(digest.into()),
                }
            }
            iota_sdk::types::UnchangedSharedKind::MutateDeleted { version } => {
                Self::MutateDeleted {
                    version: Arc::new(version.into()),
                }
            }
            iota_sdk::types::UnchangedSharedKind::ReadDeleted { version } => Self::ReadDeleted {
                version: Arc::new(version.into()),
            },
            iota_sdk::types::UnchangedSharedKind::Canceled { version } => Self::Canceled {
                version: Arc::new(version.into()),
            },
            iota_sdk::types::UnchangedSharedKind::PerEpochConfig => Self::PerEpochConfig,
            _ => unimplemented!("a new enum variant was added and needs to be handled"),
        }
    }
}

impl From<UnchangedSharedKind> for iota_sdk::types::UnchangedSharedKind {
    fn from(value: UnchangedSharedKind) -> Self {
        match value {
            UnchangedSharedKind::ReadOnlyRoot { version, digest } => Self::ReadOnlyRoot {
                version: **version,
                digest: **digest,
            },
            UnchangedSharedKind::MutateDeleted { version } => {
                Self::MutateDeleted { version: **version }
            }
            UnchangedSharedKind::ReadDeleted { version } => {
                Self::ReadDeleted { version: **version }
            }
            UnchangedSharedKind::Canceled { version } => Self::Canceled { version: **version },
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
/// object-in-missing = %d00
/// object-in-data    = %d01 u64 digest owner
/// ```
#[derive(uniffi::Enum)]
pub enum ObjectIn {
    Missing,
    /// The old version, digest and owner.
    Data {
        version: Arc<Version>,
        digest: Arc<ObjectDigest>,
        owner: Arc<Owner>,
    },
}

impl From<iota_sdk::types::ObjectIn> for ObjectIn {
    fn from(value: iota_sdk::types::ObjectIn) -> Self {
        match value {
            iota_sdk::types::ObjectIn::Missing => Self::Missing,
            iota_sdk::types::ObjectIn::Data {
                version,
                digest,
                owner,
            } => Self::Data {
                version: Arc::new(version.into()),
                digest: Arc::new(digest.into()),
                owner: Arc::new(owner.into()),
            },
            _ => unimplemented!("a new enum variant was added and needs to be handled"),
        }
    }
}

impl From<ObjectIn> for iota_sdk::types::ObjectIn {
    fn from(value: ObjectIn) -> Self {
        match value {
            ObjectIn::Missing => Self::Missing,
            ObjectIn::Data {
                version,
                digest,
                owner,
            } => Self::Data {
                version: **version,
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
/// object-out-missing        = %d00
/// object-out-object-write   = %d01 digest owner
/// object-out-package-write  = %d02 version digest
/// ```
#[derive(uniffi::Enum)]
pub enum ObjectOut {
    /// Same definition as in ObjectIn.
    Missing,
    /// Any written object, including all of mutated, created, unwrapped today.
    ObjectWrite {
        digest: Arc<ObjectDigest>,
        owner: Arc<Owner>,
    },
    /// Packages writes need to be tracked separately with version because
    /// we don't use lamport version for package publish and upgrades.
    PackageWrite {
        version: Arc<Version>,
        digest: Arc<ObjectDigest>,
    },
}

impl From<iota_sdk::types::ObjectOut> for ObjectOut {
    fn from(value: iota_sdk::types::ObjectOut) -> Self {
        match value {
            iota_sdk::types::ObjectOut::Missing => Self::Missing,
            iota_sdk::types::ObjectOut::ObjectWrite { digest, owner } => Self::ObjectWrite {
                digest: Arc::new(digest.into()),
                owner: Arc::new(owner.into()),
            },
            iota_sdk::types::ObjectOut::PackageWrite { version, digest } => Self::PackageWrite {
                version: Arc::new(version.into()),
                digest: Arc::new(digest.into()),
            },
            _ => unimplemented!("a new enum variant was added and needs to be handled"),
        }
    }
}

impl From<ObjectOut> for iota_sdk::types::ObjectOut {
    fn from(value: ObjectOut) -> Self {
        match value {
            ObjectOut::Missing => Self::Missing,
            ObjectOut::ObjectWrite { digest, owner } => Self::ObjectWrite {
                digest: **digest,
                owner: **owner,
            },
            ObjectOut::PackageWrite { version, digest } => Self::PackageWrite {
                version: **version,
                digest: **digest,
            },
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
/// id-operation-none       = %d00
/// id-operation-created    = %d01
/// id-operation-deleted    = %d02
/// ```
#[uniffi::remote(Enum)]
#[non_exhaustive]
#[repr(u8)]
pub enum IdOperation {
    None,
    Created,
    Deleted,
}

crate::export_iota_types_bcs_conversion!(
    TransactionEffectsV1,
    ChangedObject,
    UnchangedSharedObject,
    UnchangedSharedKind,
    ObjectIn,
    ObjectOut,
    IdOperation
);
crate::export_iota_types_json_conversion!(
    TransactionEffectsV1,
    ChangedObject,
    UnchangedSharedObject,
    UnchangedSharedKind,
    ObjectIn,
    ObjectOut,
    IdOperation
);
crate::export_iota_types_display!(
    TransactionEffectsV1,
    ChangedObject,
    UnchangedSharedObject,
    UnchangedSharedKind,
    ObjectIn,
    ObjectOut
);
crate::export_iota_types_remote_display!(IdOperation);
