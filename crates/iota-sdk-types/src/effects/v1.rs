// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    EffectsAuxDataDigest, EpochId, ExecutionStatus, GasCostSummary, IdOperation, InputSharedObject,
    ObjectChange, ObjectDigest, ObjectId, ObjectReference, ObjectVersion, OwnedObjectReference,
    Owner, TransactionDigest, TransactionEventsDigest, Version,
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
        w.header("Transaction Effects V1")?;
        w.child("Status", &self.status, false)?;
        w.leaf("Epoch", &self.epoch, false)?;
        w.child("Gas Cost Summary", &self.gas_cost_summary, false)?;
        w.leaf("Transaction Digest", &self.transaction_digest, false)?;
        w.option_leaf("Gas Object Index", &self.gas_object_index, false)?;
        w.option_leaf("Events Digest", &self.events_digest, false)?;
        w.leaves("Dependencies", &self.dependencies, false)?;
        w.leaf("Lamport Version", &self.lamport_version, false)?;
        w.children("Changed Objects", &self.changed_objects, false)?;
        w.children(
            "Unchanged Shared Objects",
            &self.unchanged_shared_objects,
            false,
        )?;
        w.option_leaf("Auxiliary Data Digest", &self.auxiliary_data_digest, true)
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
        w.child("Input State", &self.input_state, false)?;
        w.child("Output State", &self.output_state, false)?;
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
        w.child("Kind", &self.kind, true)
    }
}

crate::impl_tree_display!(
    TransactionEffectsV1,
    ChangedObject,
    UnchangedSharedObject,
    UnchangedSharedKind,
    ObjectIn,
    ObjectOut
);

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
///                       / %d03 u64                  ; Canceled
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
    /// Shared objects in canceled transaction. The sequence number embed
    /// cancellation reason.
    Canceled { version: Version },
    /// Read of a per-epoch config object that should remain the same during an
    /// epoch.
    PerEpochConfig,
}

impl UnchangedSharedKind {
    crate::def_is!(
        ReadOnlyRoot,
        MutateDeleted,
        ReadDeleted,
        Canceled,
        PerEpochConfig
    );
}

impl crate::TreeDisplay for UnchangedSharedKind {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.enum_name("Unchanged Shared Kind");
        match self {
            UnchangedSharedKind::ReadOnlyRoot { version, digest } => {
                w.header("Read Only Root")?;
                w.leaf("Version", version, false)?;
                w.leaf("Digest", digest, true)
            }
            UnchangedSharedKind::MutateDeleted { version } => {
                w.header("Mutate Deleted")?;
                w.leaf("Version", version, true)
            }
            UnchangedSharedKind::ReadDeleted { version } => {
                w.header("Read Deleted")?;
                w.leaf("Version", version, true)
            }
            UnchangedSharedKind::Canceled { version } => {
                w.header("Canceled")?;
                w.leaf("Version", version, true)
            }
            UnchangedSharedKind::PerEpochConfig => w.header("Per Epoch Config"),
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

impl crate::TreeDisplay for ObjectIn {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.enum_name("Object In");
        match self {
            ObjectIn::Missing => w.header("Missing"),
            ObjectIn::Data {
                version,
                digest,
                owner,
            } => {
                w.header("Data")?;
                w.leaf("Version", version, false)?;
                w.leaf("Digest", digest, false)?;
                w.leaf("Owner", owner, true)
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

impl crate::TreeDisplay for ObjectOut {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.enum_name("Object Out");
        match self {
            ObjectOut::Missing => w.header("Missing"),
            ObjectOut::ObjectWrite { digest, owner } => {
                w.header("Object Write")?;
                w.leaf("Digest", digest, false)?;
                w.leaf("Owner", owner, true)
            }
            ObjectOut::PackageWrite { version, digest } => {
                w.header("Package Write")?;
                w.leaf("Version", version, false)?;
                w.leaf("Digest", digest, true)
            }
        }
    }
}

impl TransactionEffectsV1 {
    /// The id and pre-transaction version of every object that existed before
    /// this transaction and was modified by it (mutated, wrapped or deleted).
    pub fn modified_at_versions(&self) -> Vec<ObjectVersion> {
        self.changed_objects
            .iter()
            .filter_map(|changed| {
                changed
                    .input_state
                    .version_opt()
                    .map(|version| ObjectVersion::new(changed.object_id, version))
            })
            .collect()
    }

    /// The shared objects this transaction was sequenced against, whether or
    /// not it changed them. Excludes per-epoch config objects, which need no
    /// sequencing.
    pub fn input_shared_objects(&self) -> Vec<InputSharedObject> {
        self.changed_objects
            .iter()
            .filter_map(|changed| match changed.input_state {
                ObjectIn::Data {
                    version,
                    digest,
                    owner: Owner::Shared { .. },
                } => Some(InputSharedObject::Mutate(ObjectReference::new(
                    changed.object_id,
                    version,
                    digest,
                ))),
                _ => None,
            })
            .chain(
                self.unchanged_shared_objects
                    .iter()
                    .filter_map(|unchanged| {
                        let object = |version| ObjectVersion::new(unchanged.object_id, version);
                        match unchanged.kind {
                            UnchangedSharedKind::ReadOnlyRoot { version, digest } => {
                                Some(InputSharedObject::ReadOnly(ObjectReference::new(
                                    unchanged.object_id,
                                    version,
                                    digest,
                                )))
                            }
                            UnchangedSharedKind::ReadDeleted { version } => {
                                Some(InputSharedObject::ReadDeleted(object(version)))
                            }
                            UnchangedSharedKind::MutateDeleted { version } => {
                                Some(InputSharedObject::MutateDeleted(object(version)))
                            }
                            UnchangedSharedKind::Canceled { version } => {
                                Some(InputSharedObject::Canceled(object(version)))
                            }
                            // A per-epoch config object is read without being
                            // sequenced, so it is not an input in this sense.
                            UnchangedSharedKind::PerEpochConfig => None,
                        }
                    }),
            )
            .collect()
    }

    /// What this transaction did to each object it changed, with the version
    /// and digest each side is at resolved.
    pub fn object_changes(&self) -> Vec<ObjectChange> {
        self.changed_objects
            .iter()
            .map(|changed| {
                let input = match changed.input_state {
                    ObjectIn::Data {
                        version, digest, ..
                    } => Some((version, digest)),
                    _ => None,
                };
                let output = match changed.output_state {
                    ObjectOut::ObjectWrite { digest, .. } => Some((self.lamport_version, digest)),
                    ObjectOut::PackageWrite { version, digest } => Some((version, digest)),
                    _ => None,
                };
                ObjectChange {
                    object_id: changed.object_id,
                    input_version: input.map(|(version, _)| version),
                    input_digest: input.map(|(_, digest)| digest),
                    output_version: output.map(|(version, _)| version),
                    output_digest: output.map(|(_, digest)| digest),
                    id_operation: changed.id_operation,
                }
            })
            .collect()
    }

    /// The reference and owner, before this transaction, of every object it
    /// modified.
    pub fn old_object_metadata(&self) -> Vec<OwnedObjectReference> {
        self.changed_objects
            .iter()
            .filter_map(|changed| match changed.input_state {
                ObjectIn::Data {
                    version,
                    digest,
                    owner,
                } => Some(OwnedObjectReference::new(
                    ObjectReference::new(changed.object_id, version, digest),
                    owner,
                )),
                _ => None,
            })
            .collect()
    }

    /// Objects (Move objects and packages) newly created by this transaction,
    /// paired with their owner. Excludes objects created and then wrapped
    /// within the same transaction.
    pub fn created(&self) -> Vec<OwnedObjectReference> {
        self.changed_objects
            .iter()
            .filter(|changed| {
                changed.input_state.is_missing() && changed.id_operation == IdOperation::Created
            })
            .filter_map(|changed| self.output_reference(changed))
            .collect()
    }

    /// Objects that existed before this transaction and whose contents it
    /// updated (in-place mutations and system package upgrades), at their
    /// post-transaction reference and owner.
    pub fn mutated(&self) -> Vec<OwnedObjectReference> {
        self.changed_objects
            .iter()
            .filter(|changed| changed.input_state.is_data())
            .filter_map(|changed| self.output_reference(changed))
            .collect()
    }

    /// Objects that were wrapped inside another object before this transaction
    /// and that it promoted back to top-level objects in the store.
    pub fn unwrapped(&self) -> Vec<OwnedObjectReference> {
        self.changed_objects
            .iter()
            .filter(|changed| {
                changed.input_state.is_missing()
                    && changed.id_operation == IdOperation::None
                    // A package is never wrapped, so never unwrapped either.
                    && changed.output_state.is_object_write()
            })
            .filter_map(|changed| self.output_reference(changed))
            .collect()
    }

    /// Objects that existed before this transaction and that it deleted.
    /// References carry the version this transaction assigned and the
    /// [`ObjectDigest::OBJECT_DELETED`] tombstone digest.
    pub fn deleted(&self) -> Vec<ObjectReference> {
        self.removed_references(
            |changed| changed.input_state.is_data() && changed.id_operation == IdOperation::Deleted,
            ObjectDigest::OBJECT_DELETED,
        )
    }

    /// Objects unwrapped and then deleted within this same transaction, so
    /// that they existed as top-level objects neither before nor after it.
    /// References carry the version this transaction assigned and the
    /// [`ObjectDigest::OBJECT_DELETED`] tombstone digest.
    pub fn unwrapped_then_deleted(&self) -> Vec<ObjectReference> {
        self.removed_references(
            |changed| {
                changed.input_state.is_missing() && changed.id_operation == IdOperation::Deleted
            },
            ObjectDigest::OBJECT_DELETED,
        )
    }

    /// Objects that existed as top-level objects before this transaction and
    /// that it wrapped inside another object, so they are no longer visible in
    /// the object store. References carry the version this transaction assigned
    /// and the [`ObjectDigest::OBJECT_WRAPPED`] tombstone digest.
    pub fn wrapped(&self) -> Vec<ObjectReference> {
        self.removed_references(
            |changed| changed.input_state.is_data() && changed.id_operation == IdOperation::None,
            ObjectDigest::OBJECT_WRAPPED,
        )
    }

    /// The post-transaction reference and owner of the gas object, or `None`
    /// for a transaction that requires no gas (a system transaction).
    pub fn gas_object(&self) -> Option<OwnedObjectReference> {
        let changed = self.changed_objects.get(self.gas_object_index? as usize)?;
        // Gas is paid in coins, so a gas object is never a package.
        changed
            .output_state
            .is_object_write()
            .then(|| self.output_reference(changed))?
    }

    /// The post-transaction reference and owner of a changed object, or `None`
    /// if this transaction removed it from the store. A package carries its own
    /// version; every other object takes the version this transaction assigned.
    fn output_reference(&self, changed: &ChangedObject) -> Option<OwnedObjectReference> {
        match changed.output_state {
            ObjectOut::ObjectWrite { digest, owner } => Some(OwnedObjectReference::new(
                ObjectReference::new(changed.object_id, self.lamport_version, digest),
                owner,
            )),
            ObjectOut::PackageWrite { version, digest } => Some(OwnedObjectReference::new(
                ObjectReference::new(changed.object_id, version, digest),
                Owner::Immutable,
            )),
            _ => None,
        }
    }

    /// References, carrying `digest` as their tombstone, to the objects this
    /// transaction removed from the store that `select` accepts.
    fn removed_references(
        &self,
        select: impl Fn(&ChangedObject) -> bool,
        digest: ObjectDigest,
    ) -> Vec<ObjectReference> {
        self.changed_objects
            .iter()
            .filter(|changed| changed.output_state.is_missing() && select(changed))
            .map(|changed| ObjectReference::new(changed.object_id, self.lamport_version, digest))
            .collect()
    }
}

#[cfg(all(feature = "proptest", test))]
mod tests {
    use test_strategy::proptest;

    use super::TransactionEffectsV1;

    /// The six object sets are selected by mutually exclusive combinations of
    /// input state, output state and id operation, so together they report each
    /// changed object at most once — for any effects, not only well-formed
    /// ones. The fixtures cover the other half, that real effects leave none
    /// out.
    #[proptest]
    fn object_sets_report_each_changed_object_at_most_once(effects: TransactionEffectsV1) {
        let reported = effects.created().len()
            + effects.mutated().len()
            + effects.unwrapped().len()
            + effects.deleted().len()
            + effects.unwrapped_then_deleted().len()
            + effects.wrapped().len();

        assert!(reported <= effects.changed_objects.len());
    }
}
