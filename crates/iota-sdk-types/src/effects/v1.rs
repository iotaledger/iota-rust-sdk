// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    EffectsAuxDataDigest, EpochId, ExecutionStatus, GasCostSummary, IdOperation, ObjectDigest,
    ObjectId, Owner, TransactionDigest, TransactionEventsDigest, Version,
};

/// Version 1 of TransactionEffects
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// transaction-effects-v1 = execution-status                    ; status
///                          u64                                 ; epoch
///                          gas-cost-summary                    ; gas-used
///                          transaction-digest                  ; transaction-digest
///                          (option u32)                        ; gas-object-index
///                          (option transaction-events-digest)  ; events-digest
///                          (vector transaction-digest)         ; dependencies
///                          u64                                 ; lamport-version
///                          (vector changed-object)             ; changed-objects
///                          (vector unchanged-shared-object)    ; unchanged-shared-objects
///                          (option effects-aux-data-digest)    ; auxiliary-data-digest
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
pub struct TransactionEffectsV1 {
    /// The status of the execution
    pub status: ExecutionStatus,
    /// The epoch when this transaction was executed.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "bcs-schema", bcs_schema(as_type = "u64"))]
    pub epoch: EpochId,
    /// The gas used by this transaction
    pub gas_cost_summary: GasCostSummary,
    /// The transaction digest
    pub transaction_digest: TransactionDigest,
    /// The updated gas object reference, as an index into the `changed_objects`
    /// vector. Having a dedicated field for convenient access.
    /// System transaction that don't require gas will leave this as None.
    pub gas_object_index: Option<u32>,
    /// The digest of the events emitted during execution,
    /// can be None if the transaction does not emit any event.
    pub events_digest: Option<TransactionEventsDigest>,
    /// The set of transaction digests this transaction depends on.
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=5).lift()))]
    pub dependencies: Vec<TransactionDigest>,
    /// The version number of all the written Move objects by this transaction.
    pub lamport_version: Version,
    /// Objects whose state are changed in the object store.
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=2).lift()))]
    pub changed_objects: Vec<ChangedObject>,
    /// Shared objects that are not mutated in this transaction. Unlike owned
    /// objects, read-only shared objects' version are not committed in the
    /// transaction, and in order for a node to catch up and execute it
    /// without consensus sequencing, the version needs to be committed in
    /// the effects.
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=2).lift()))]
    pub unchanged_shared_objects: Vec<UnchangedSharedObject>,
    /// Auxiliary data that are not protocol-critical, generated as part of the
    /// effects but are stored separately. Storing it separately allows us
    /// to avoid bloating the effects with data that are not critical.
    /// It also provides more flexibility on the format and type of the data.
    pub auxiliary_data_digest: Option<EffectsAuxDataDigest>,
}

impl crate::TreeDisplay for TransactionEffectsV1 {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Transaction Effects")?;
        w.leaf("Status", &self.status, false)?;
        w.leaf("Epoch", &self.epoch, false)?;
        w.child("Gas Cost Summary", &self.gas_cost_summary, false)?;
        w.leaf("Transaction Digest", &self.transaction_digest, false)?;
        w.option("Gas Object Index", &self.gas_object_index, false)?;
        w.option("Events Digest", &self.events_digest, false)?;
        w.iter_inline("Dependencies", &self.dependencies, false)?;
        w.leaf("Lamport Version", &self.lamport_version, false)?;
        w.vec_children("Changed Objects", &self.changed_objects, false)?;
        w.vec_children(
            "Unchanged Shared Objects",
            &self.unchanged_shared_objects,
            false,
        )?;
        w.option("Auxiliary Data Digest", &self.auxiliary_data_digest, true)
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
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
pub struct ChangedObject {
    /// Id of the object
    pub object_id: ObjectId,
    /// State of the object in the store prior to this transaction.
    pub input_state: ObjectIn,
    /// State of the object in the store after this transaction.
    pub output_state: ObjectOut,
    /// Whether this object ID is created or deleted in this transaction.
    /// This information isn't required by the protocol but is useful for
    /// providing more detailed semantics on object changes.
    pub id_operation: IdOperation,
}

impl crate::TreeDisplay for ChangedObject {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Changed Object")?;
        w.leaf("Object ID", &self.object_id, false)?;
        w.leaf("Input State", &self.input_state, false)?;
        w.leaf("Output State", &self.output_state, false)?;
        w.leaf("ID Operation", &self.id_operation, true)
    }
}

/// A shared object that wasn't changed during execution
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// unchanged-shared-object = object-id               ; object-id
///                           unchanged-shared-kind   ; kind
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
pub struct UnchangedSharedObject {
    pub object_id: ObjectId,
    pub kind: UnchangedSharedKind,
}

impl crate::TreeDisplay for UnchangedSharedObject {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Unchanged Shared Object")?;
        w.leaf("Object ID", &self.object_id, false)?;
        w.leaf("Kind", &self.kind, true)
    }
}

crate::impl_tree_display!(TransactionEffectsV1, ChangedObject, UnchangedSharedObject);

/// Type of unchanged shared object
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// unchanged-shared-kind = %d00 u64 object-digest   ; ReadOnlyRoot
///                       / %d01 u64                  ; MutateDeleted
///                       / %d02 u64                  ; ReadDeleted
///                       / %d03 u64                  ; Cancelled
///                       / %d04                       ; PerEpochConfig
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
#[non_exhaustive]
pub enum UnchangedSharedKind {
    /// Read-only shared objects from the input. We don't really need
    /// ObjectDigest for protocol correctness, but it will make it easier to
    /// verify untrusted read.
    ReadOnlyRoot {
        version: Version,
        digest: ObjectDigest,
    },
    /// Deleted shared objects that appear mutably/owned in the input.
    MutateDeleted { version: Version },
    /// Deleted shared objects that appear as read-only in the input.
    ReadDeleted { version: Version },
    /// Shared objects in cancelled transaction. The sequence number embed
    /// cancellation reason.
    Cancelled { version: Version },
    /// Read of a per-epoch config object that should remain the same during an
    /// epoch.
    PerEpochConfig,
}

impl UnchangedSharedKind {
    crate::def_is!(
        ReadOnlyRoot,
        MutateDeleted,
        ReadDeleted,
        Cancelled,
        PerEpochConfig
    );
}

impl std::fmt::Display for UnchangedSharedKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnchangedSharedKind::ReadOnlyRoot { version, digest } => {
                write!(f, "ReadOnlyRoot(version: {version}, digest: {digest})")
            }
            UnchangedSharedKind::MutateDeleted { version } => {
                write!(f, "MutateDeleted(version: {version})")
            }
            UnchangedSharedKind::ReadDeleted { version } => {
                write!(f, "ReadDeleted(version: {version})")
            }
            UnchangedSharedKind::Cancelled { version } => {
                write!(f, "Cancelled(version: {version})")
            }
            UnchangedSharedKind::PerEpochConfig => {
                write!(f, "PerEpochConfig")
            }
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
/// object-in = %d00                          ; Missing
///           / %d01 u64 object-digest owner   ; Data
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
#[non_exhaustive]
pub enum ObjectIn {
    Missing,
    /// The old version, digest and owner.
    Data {
        version: Version,
        digest: ObjectDigest,
        owner: Owner,
    },
}

impl ObjectIn {
    crate::def_is!(Missing, Data);

    pub fn version_opt(&self) -> Option<Version> {
        if let Self::Data { version, .. } = self {
            Some(*version)
        } else {
            None
        }
    }

    pub fn version(&self) -> Version {
        self.version_opt().expect("object does not exist")
    }

    pub fn digest_opt(&self) -> Option<ObjectDigest> {
        if let Self::Data { digest, .. } = self {
            Some(*digest)
        } else {
            None
        }
    }

    pub fn digest(&self) -> ObjectDigest {
        self.digest_opt().expect("object does not exist")
    }

    pub fn owner_opt(&self) -> Option<Owner> {
        if let Self::Data { owner, .. } = self {
            Some(*owner)
        } else {
            None
        }
    }

    pub fn owner(&self) -> Owner {
        self.owner_opt().expect("object does not exist")
    }
}

impl std::fmt::Display for ObjectIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObjectIn::Missing => write!(f, "Missing"),
            ObjectIn::Data {
                version,
                digest,
                owner,
            } => {
                write!(
                    f,
                    "Data(version: {version}, digest: {digest}, owner: {owner})"
                )
            }
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
/// object-out = %d00                       ; Missing
///            / %d01 object-digest owner   ; ObjectWrite
///            / %d02 u64 object-digest     ; PackageWrite
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
#[non_exhaustive]
pub enum ObjectOut {
    /// Same definition as in ObjectIn.
    Missing,
    /// Any written object, including all of mutated, created, unwrapped today.
    ObjectWrite { digest: ObjectDigest, owner: Owner },
    /// Packages writes need to be tracked separately with version because
    /// we don't use lamport version for package publish and upgrades.
    PackageWrite {
        version: Version,
        digest: ObjectDigest,
    },
}

impl ObjectOut {
    crate::def_is!(Missing, ObjectWrite, PackageWrite);

    pub fn object_digest_opt(&self) -> Option<ObjectDigest> {
        if let Self::ObjectWrite { digest, .. } = self {
            Some(*digest)
        } else {
            None
        }
    }

    pub fn object_digest(&self) -> ObjectDigest {
        self.object_digest_opt().expect("object does not exist")
    }

    pub fn object_owner_opt(&self) -> Option<Owner> {
        if let Self::ObjectWrite { owner, .. } = self {
            Some(*owner)
        } else {
            None
        }
    }

    pub fn object_owner(&self) -> Owner {
        self.object_owner_opt().expect("object does not exist")
    }

    pub fn package_version_opt(&self) -> Option<Version> {
        if let Self::PackageWrite { version, .. } = self {
            Some(*version)
        } else {
            None
        }
    }

    pub fn package_version(&self) -> Version {
        self.package_version_opt().expect("object does not exist")
    }

    pub fn package_digest_opt(&self) -> Option<ObjectDigest> {
        if let Self::PackageWrite { digest, .. } = self {
            Some(*digest)
        } else {
            None
        }
    }

    pub fn package_digest(&self) -> ObjectDigest {
        self.package_digest_opt().expect("package does not exist")
    }
}

impl std::fmt::Display for ObjectOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObjectOut::Missing => write!(f, "Missing"),
            ObjectOut::ObjectWrite { digest, owner } => {
                write!(f, "ObjectWrite(digest: {digest}, owner: {owner})")
            }
            ObjectOut::PackageWrite { version, digest } => {
                write!(f, "PackageWrite(version: {version}, digest: {digest})")
            }
        }
    }
}
