// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::types::{
    digest::{EffectsAuxDataDigest, ObjectDigest, TransactionDigest, TransactionEventsDigest},
    execution_status::ExecutionStatus,
    gas::GasCostSummary,
    object::{ObjectId, ObjectReference, Owner},
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
#[derive(Clone, Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct TransactionEffectsV1(pub iota_sdk::types::TransactionEffectsV1);

#[uniffi::export]
impl TransactionEffectsV1 {
    #[uniffi::constructor]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        status: ExecutionStatus,
        epoch: u64,
        gas_cost_summary: GasCostSummary,
        transaction_digest: &TransactionDigest,
        gas_object_index: Option<u32>,
        events_digest: Option<Arc<TransactionEventsDigest>>,
        dependencies: Vec<Arc<TransactionDigest>>,
        lamport_version: &Version,
        changed_objects: Vec<ChangedObject>,
        unchanged_shared_objects: Vec<UnchangedSharedObject>,
        auxiliary_data_digest: Option<Arc<EffectsAuxDataDigest>>,
    ) -> Self {
        Self(iota_sdk::types::TransactionEffectsV1 {
            status: status.into(),
            epoch,
            gas_cost_summary: gas_cost_summary.into(),
            transaction_digest: **transaction_digest,
            gas_object_index,
            events_digest: events_digest.map(|digest| **digest),
            dependencies: dependencies.into_iter().map(|digest| **digest).collect(),
            lamport_version: **lamport_version,
            changed_objects: changed_objects.into_iter().map(Into::into).collect(),
            unchanged_shared_objects: unchanged_shared_objects
                .into_iter()
                .map(Into::into)
                .collect(),
            auxiliary_data_digest: auxiliary_data_digest.map(|digest| **digest),
        })
    }

    /// The status of the execution.
    pub fn status(&self) -> ExecutionStatus {
        self.0.status.clone().into()
    }

    /// The epoch when this transaction was executed.
    pub fn epoch(&self) -> u64 {
        self.0.epoch
    }

    /// The gas used by this transaction.
    pub fn gas_cost_summary(&self) -> GasCostSummary {
        self.0.gas_cost_summary.clone().into()
    }

    /// The transaction digest.
    pub fn transaction_digest(&self) -> TransactionDigest {
        self.0.transaction_digest.into()
    }

    /// The updated gas object, as an index into `changed_objects`. `None` for a
    /// system transaction, which pays no gas.
    pub fn gas_object_index(&self) -> Option<u32> {
        self.0.gas_object_index
    }

    /// The digest of the events emitted during execution, or `None` if the
    /// transaction emitted none.
    pub fn events_digest(&self) -> Option<Arc<TransactionEventsDigest>> {
        self.0.events_digest.map(|digest| Arc::new(digest.into()))
    }

    /// The transactions this one depends on.
    pub fn dependencies(&self) -> Vec<Arc<TransactionDigest>> {
        self.0
            .dependencies
            .iter()
            .map(|digest| Arc::new((*digest).into()))
            .collect()
    }

    /// The version this transaction assigned to every output object other than
    /// packages.
    pub fn lamport_version(&self) -> Version {
        self.0.lamport_version.into()
    }

    /// Objects whose state changed in the object store.
    pub fn changed_objects(&self) -> Vec<ChangedObject> {
        self.0
            .changed_objects
            .iter()
            .cloned()
            .map(Into::into)
            .collect()
    }

    /// Shared objects this transaction was sequenced against without changing.
    pub fn unchanged_shared_objects(&self) -> Vec<UnchangedSharedObject> {
        self.0
            .unchanged_shared_objects
            .iter()
            .cloned()
            .map(Into::into)
            .collect()
    }

    /// Auxiliary data generated as part of the effects but stored separately.
    pub fn auxiliary_data_digest(&self) -> Option<Arc<EffectsAuxDataDigest>> {
        self.0
            .auxiliary_data_digest
            .map(|digest| Arc::new(digest.into()))
    }

    /// The id and pre-transaction version of every object that existed before
    /// this transaction and was modified by it.
    pub fn modified_at_versions(&self) -> Vec<ObjectVersion> {
        self.0
            .modified_at_versions()
            .into_iter()
            .map(Into::into)
            .collect()
    }

    /// The reference and owner, before this transaction, of every object it
    /// modified.
    pub fn old_object_metadata(&self) -> Vec<OwnedObjectReference> {
        self.0
            .old_object_metadata()
            .into_iter()
            .map(Into::into)
            .collect()
    }

    /// Objects newly created by this transaction, paired with their owner.
    pub fn created(&self) -> Vec<OwnedObjectReference> {
        self.0.created().into_iter().map(Into::into).collect()
    }

    /// Objects that existed before this transaction and whose contents it
    /// updated, at their post-transaction reference and owner.
    pub fn mutated(&self) -> Vec<OwnedObjectReference> {
        self.0.mutated().into_iter().map(Into::into).collect()
    }

    /// Objects that were wrapped inside another object before this transaction
    /// and that it restored to the store.
    pub fn unwrapped(&self) -> Vec<OwnedObjectReference> {
        self.0.unwrapped().into_iter().map(Into::into).collect()
    }

    /// Objects that existed before this transaction and that it deleted.
    pub fn deleted(&self) -> Vec<ObjectReference> {
        self.0.deleted().into_iter().map(Into::into).collect()
    }

    /// Objects unwrapped and then deleted within this same transaction.
    pub fn unwrapped_then_deleted(&self) -> Vec<ObjectReference> {
        self.0
            .unwrapped_then_deleted()
            .into_iter()
            .map(Into::into)
            .collect()
    }

    /// Objects that this transaction wrapped inside another object.
    pub fn wrapped(&self) -> Vec<ObjectReference> {
        self.0.wrapped().into_iter().map(Into::into).collect()
    }

    /// The shared objects this transaction was sequenced against, whether or
    /// not it changed them.
    pub fn input_shared_objects(&self) -> Vec<InputSharedObject> {
        self.0
            .input_shared_objects()
            .into_iter()
            .map(Into::into)
            .collect()
    }

    /// Every object still in the store after this transaction, tagged with how
    /// it got there.
    pub fn all_changed_objects(&self) -> Vec<ChangedObjectWrite> {
        self.0
            .all_changed_objects()
            .into_iter()
            .map(|(object, kind)| ChangedObjectWrite {
                object: object.into(),
                kind: kind.into(),
            })
            .collect()
    }

    /// Every object that was in the store before this transaction and is not
    /// after it, tagged with why.
    pub fn all_removed_objects(&self) -> Vec<RemovedObject> {
        self.0
            .all_removed_objects()
            .into_iter()
            .map(|(reference, kind)| RemovedObject {
                reference: reference.into(),
                kind: kind.into(),
            })
            .collect()
    }

    /// The post-transaction reference and owner of the gas object, or `None`
    /// for a system transaction, which pays no gas.
    pub fn gas_object(&self) -> Option<OwnedObjectReference> {
        self.0.gas_object().map(Into::into)
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
#[derive(Clone, uniffi::Record)]
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
            id_operation: value.id_operation.into(),
        }
    }
}

impl From<ChangedObject> for iota_sdk::types::ChangedObject {
    fn from(value: ChangedObject) -> Self {
        Self {
            object_id: **value.object_id,
            input_state: value.input_state.into(),
            output_state: value.output_state.into(),
            id_operation: value.id_operation.into(),
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
#[derive(Clone, uniffi::Record)]
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
#[derive(Clone, uniffi::Enum)]
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
#[derive(Clone, uniffi::Enum)]
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
#[derive(Clone, uniffi::Enum)]
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
#[derive(Clone, uniffi::Enum)]
#[repr(u8)]
pub enum IdOperation {
    None,
    Created,
    Deleted,
}

impl From<iota_sdk::types::IdOperation> for IdOperation {
    fn from(value: iota_sdk::types::IdOperation) -> Self {
        match value {
            iota_sdk::types::IdOperation::None => Self::None,
            iota_sdk::types::IdOperation::Created => Self::Created,
            iota_sdk::types::IdOperation::Deleted => Self::Deleted,
            _ => unimplemented!("a new IdOperation variant was added and needs to be handled"),
        }
    }
}

impl From<IdOperation> for iota_sdk::types::IdOperation {
    fn from(value: IdOperation) -> Self {
        match value {
            IdOperation::None => Self::None,
            IdOperation::Created => Self::Created,
            IdOperation::Deleted => Self::Deleted,
        }
    }
}

crate::export_iota_types_objects_bcs_conversion!(TransactionEffectsV1);
crate::export_iota_types_objects_json_conversion!(TransactionEffectsV1);
crate::export_iota_types_bcs_conversion!(
    ChangedObject,
    UnchangedSharedObject,
    UnchangedSharedKind,
    ObjectIn,
    ObjectOut,
    IdOperation
);
crate::export_iota_types_json_conversion!(
    ChangedObject,
    UnchangedSharedObject,
    UnchangedSharedKind,
    ObjectIn,
    ObjectOut,
    IdOperation
);
crate::export_iota_types_objects_display!(TransactionEffectsV1);
crate::export_iota_types_display!(
    ChangedObject,
    UnchangedSharedObject,
    UnchangedSharedKind,
    ObjectIn,
    ObjectOut,
    IdOperation
);

/// An object reference paired with the owner the object has at that version.
#[derive(uniffi::Record)]
pub struct OwnedObjectReference {
    pub reference: ObjectReference,
    pub owner: Arc<Owner>,
}

impl From<iota_sdk::types::OwnedObjectReference> for OwnedObjectReference {
    fn from(value: iota_sdk::types::OwnedObjectReference) -> Self {
        Self {
            reference: value.reference.into(),
            owner: Arc::new(value.owner.into()),
        }
    }
}

/// An object id paired with one of that object's versions.
#[derive(uniffi::Record)]
pub struct ObjectVersion {
    pub object_id: Arc<ObjectId>,
    pub version: Arc<Version>,
}

impl From<iota_sdk::types::ObjectVersion> for ObjectVersion {
    fn from(value: iota_sdk::types::ObjectVersion) -> Self {
        Self {
            object_id: Arc::new(value.object_id.into()),
            version: Arc::new(value.version.into()),
        }
    }
}

/// A shared object an executed transaction took as input.
#[derive(uniffi::Enum)]
pub enum InputSharedObject {
    /// Taken mutably, and written back by the transaction.
    Mutate { reference: ObjectReference },
    /// Read without being mutated.
    ReadOnly { reference: ObjectReference },
    /// Read, but already deleted by an earlier transaction.
    ReadDeleted { object: ObjectVersion },
    /// Taken mutably, but already deleted by an earlier transaction.
    MutateDeleted { object: ObjectVersion },
    /// Taken by a transaction that consensus canceled.
    Canceled { object: ObjectVersion },
}

impl From<iota_sdk::types::InputSharedObject> for InputSharedObject {
    fn from(value: iota_sdk::types::InputSharedObject) -> Self {
        match value {
            iota_sdk::types::InputSharedObject::Mutate(reference) => Self::Mutate {
                reference: reference.into(),
            },
            iota_sdk::types::InputSharedObject::ReadOnly(reference) => Self::ReadOnly {
                reference: reference.into(),
            },
            iota_sdk::types::InputSharedObject::ReadDeleted(object) => Self::ReadDeleted {
                object: object.into(),
            },
            iota_sdk::types::InputSharedObject::MutateDeleted(object) => Self::MutateDeleted {
                object: object.into(),
            },
            iota_sdk::types::InputSharedObject::Canceled(object) => Self::Canceled {
                object: object.into(),
            },
        }
    }
}

/// How an object came to be in the store after a transaction wrote it.
#[derive(uniffi::Enum)]
pub enum WriteKind {
    /// The object existed already and the transaction changed its contents.
    Mutate,
    /// The transaction created the object.
    Create,
    /// The object was wrapped inside another object, and the transaction
    /// restored it to the store.
    Unwrap,
}

impl From<iota_sdk::types::WriteKind> for WriteKind {
    fn from(value: iota_sdk::types::WriteKind) -> Self {
        match value {
            iota_sdk::types::WriteKind::Mutate => Self::Mutate,
            iota_sdk::types::WriteKind::Create => Self::Create,
            iota_sdk::types::WriteKind::Unwrap => Self::Unwrap,
        }
    }
}

/// Why an object is no longer in the store after a transaction.
#[derive(uniffi::Enum)]
pub enum ObjectRemoveKind {
    /// The transaction deleted the object.
    Delete,
    /// The transaction wrapped the object inside another one.
    Wrap,
}

impl From<iota_sdk::types::ObjectRemoveKind> for ObjectRemoveKind {
    fn from(value: iota_sdk::types::ObjectRemoveKind) -> Self {
        match value {
            iota_sdk::types::ObjectRemoveKind::Delete => Self::Delete,
            iota_sdk::types::ObjectRemoveKind::Wrap => Self::Wrap,
        }
    }
}

/// An object still in the store after a transaction, and how it got there.
#[derive(uniffi::Record)]
pub struct ChangedObjectWrite {
    pub object: OwnedObjectReference,
    pub kind: WriteKind,
}

/// An object no longer in the store after a transaction, and why.
#[derive(uniffi::Record)]
pub struct RemovedObject {
    pub reference: ObjectReference,
    pub kind: ObjectRemoveKind,
}
