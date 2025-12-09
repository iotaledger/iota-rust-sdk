// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    Digest, EpochId, GasCostSummary, ObjectId,
    execution_status::ExecutionStatus,
    object::{Owner, Version},
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
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct TransactionEffectsV1 {
    /// The status of the execution
    #[cfg_attr(feature = "schemars", schemars(flatten))]
    pub status: ExecutionStatus,
    /// The epoch when this transaction was executed.
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub epoch: EpochId,
    /// The gas used by this transaction
    pub gas_used: GasCostSummary,
    /// The transaction digest
    pub transaction_digest: Digest,
    /// The updated gas object reference, as an index into the `changed_objects`
    /// vector. Having a dedicated field for convenient access.
    /// System transaction that don't require gas will leave this as None.
    pub gas_object_index: Option<u32>,
    /// The digest of the events emitted during execution,
    /// can be None if the transaction does not emit any event.
    pub events_digest: Option<Digest>,
    /// The set of transaction digests this transaction depends on.
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(0..=5).lift()))]
    pub dependencies: Vec<Digest>,
    /// The version number of all the written Move objects by this transaction.
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
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
    pub auxiliary_data_digest: Option<Digest>,
}

impl TransactionEffectsV1 {
    /// The status of the execution
    pub fn status(&self) -> &ExecutionStatus {
        &self.status
    }

    /// The epoch when this transaction was executed.
    pub fn epoch(&self) -> EpochId {
        self.epoch
    }

    /// The gas used in this transaction.
    pub fn gas_summary(&self) -> &GasCostSummary {
        &self.gas_used
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
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
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

/// A shared object that wasn't changed during execution
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// unchanged-shared-object = object-id unchanged-shared-object-kind
/// ```
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct UnchangedSharedObject {
    pub object_id: ObjectId,
    pub kind: UnchangedSharedKind,
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
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(
    feature = "schemars",
    derive(schemars::JsonSchema),
    schemars(tag = "kind", rename_all = "snake_case")
)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub enum UnchangedSharedKind {
    /// Read-only shared objects from the input. We don't really need
    /// ObjectDigest for protocol correctness, but it will make it easier to
    /// verify untrusted read.
    ReadOnlyRoot {
        #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
        version: Version,
        digest: Digest,
    },
    /// Deleted shared objects that appear mutably/owned in the input.
    MutateDeleted {
        #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
        version: Version,
    },
    /// Deleted shared objects that appear as read-only in the input.
    ReadDeleted {
        #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
        version: Version,
    },
    /// Shared objects in cancelled transaction. The sequence number embed
    /// cancellation reason.
    Cancelled {
        #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
        version: Version,
    },
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
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(
    feature = "schemars",
    derive(schemars::JsonSchema),
    schemars(tag = "state", rename_all = "snake_case")
)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub enum ObjectIn {
    Missing,
    /// The old version, digest and owner.
    Data {
        #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
        version: Version,
        digest: Digest,
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

    pub fn digest_opt(&self) -> Option<Digest> {
        if let Self::Data { digest, .. } = self {
            Some(*digest)
        } else {
            None
        }
    }

    pub fn digest(&self) -> Digest {
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
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(
    feature = "schemars",
    derive(schemars::JsonSchema),
    schemars(tag = "state", rename_all = "snake_case")
)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub enum ObjectOut {
    /// Same definition as in ObjectIn.
    Missing,
    /// Any written object, including all of mutated, created, unwrapped today.
    ObjectWrite { digest: Digest, owner: Owner },
    /// Packages writes need to be tracked separately with version because
    /// we don't use lamport version for package publish and upgrades.
    PackageWrite {
        #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
        version: Version,
        digest: Digest,
    },
}

impl ObjectOut {
    crate::def_is!(Missing, ObjectWrite, PackageWrite);

    pub fn object_digest_opt(&self) -> Option<Digest> {
        if let Self::ObjectWrite { digest, .. } = self {
            Some(*digest)
        } else {
            None
        }
    }

    pub fn object_digest(&self) -> Digest {
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

    pub fn package_digest_opt(&self) -> Option<Digest> {
        if let Self::PackageWrite { digest, .. } = self {
            Some(*digest)
        } else {
            None
        }
    }

    pub fn package_digest(&self) -> Digest {
        self.package_digest_opt().expect("package does not exist")
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
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "lowercase")
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub enum IdOperation {
    None,
    Created,
    Deleted,
}

impl IdOperation {
    crate::def_is!(None, Created, Deleted);
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    #[derive(serde::Serialize)]
    struct ReadableTransactionEffectsV1Ref<'a> {
        #[serde(flatten)]
        status: &'a ExecutionStatus,
        #[serde(with = "crate::_serde::ReadableDisplay")]
        epoch: &'a EpochId,
        gas_used: &'a GasCostSummary,
        transaction_digest: &'a Digest,
        gas_object_index: &'a Option<u32>,
        events_digest: &'a Option<Digest>,
        dependencies: &'a Vec<Digest>,
        #[serde(with = "crate::_serde::ReadableDisplay")]
        lamport_version: &'a Version,
        changed_objects: &'a Vec<ChangedObject>,
        unchanged_shared_objects: &'a Vec<UnchangedSharedObject>,
        auxiliary_data_digest: &'a Option<Digest>,
    }

    #[derive(serde::Deserialize)]
    struct ReadableTransactionEffectsV1 {
        #[serde(flatten)]
        status: ExecutionStatus,
        #[serde(with = "crate::_serde::ReadableDisplay")]
        epoch: EpochId,
        gas_used: GasCostSummary,
        transaction_digest: Digest,
        gas_object_index: Option<u32>,
        events_digest: Option<Digest>,
        dependencies: Vec<Digest>,
        #[serde(with = "crate::_serde::ReadableDisplay")]
        lamport_version: Version,
        changed_objects: Vec<ChangedObject>,
        unchanged_shared_objects: Vec<UnchangedSharedObject>,
        auxiliary_data_digest: Option<Digest>,
    }

    #[derive(serde::Serialize)]
    struct BinaryTransactionEffectsV1Ref<'a> {
        status: &'a ExecutionStatus,
        epoch: &'a EpochId,
        gas_used: &'a GasCostSummary,
        transaction_digest: &'a Digest,
        gas_object_index: &'a Option<u32>,
        events_digest: &'a Option<Digest>,
        dependencies: &'a Vec<Digest>,
        lamport_version: &'a Version,
        changed_objects: &'a Vec<ChangedObject>,
        unchanged_shared_objects: &'a Vec<UnchangedSharedObject>,
        auxiliary_data_digest: &'a Option<Digest>,
    }

    #[derive(serde::Deserialize)]
    struct BinaryTransactionEffectsV1 {
        status: ExecutionStatus,
        epoch: EpochId,
        gas_used: GasCostSummary,
        transaction_digest: Digest,
        gas_object_index: Option<u32>,
        events_digest: Option<Digest>,
        dependencies: Vec<Digest>,
        lamport_version: Version,
        changed_objects: Vec<ChangedObject>,
        unchanged_shared_objects: Vec<UnchangedSharedObject>,
        auxiliary_data_digest: Option<Digest>,
    }

    impl Serialize for TransactionEffectsV1 {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let Self {
                status,
                epoch,
                gas_used,
                transaction_digest,
                gas_object_index,
                events_digest,
                dependencies,
                lamport_version,
                changed_objects,
                unchanged_shared_objects,
                auxiliary_data_digest,
            } = self;
            if serializer.is_human_readable() {
                let readable = ReadableTransactionEffectsV1Ref {
                    status,
                    epoch,
                    gas_used,
                    transaction_digest,
                    gas_object_index,
                    events_digest,
                    dependencies,
                    lamport_version,
                    changed_objects,
                    unchanged_shared_objects,
                    auxiliary_data_digest,
                };
                readable.serialize(serializer)
            } else {
                let binary = BinaryTransactionEffectsV1Ref {
                    status,
                    epoch,
                    gas_used,
                    transaction_digest,
                    gas_object_index,
                    events_digest,
                    dependencies,
                    lamport_version,
                    changed_objects,
                    unchanged_shared_objects,
                    auxiliary_data_digest,
                };
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for TransactionEffectsV1 {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let ReadableTransactionEffectsV1 {
                    status,
                    epoch,
                    gas_used,
                    transaction_digest,
                    gas_object_index,
                    events_digest,
                    dependencies,
                    lamport_version,
                    changed_objects,
                    unchanged_shared_objects,
                    auxiliary_data_digest,
                } = Deserialize::deserialize(deserializer)?;
                Ok(Self {
                    status,
                    epoch,
                    gas_used,
                    transaction_digest,
                    gas_object_index,
                    events_digest,
                    dependencies,
                    lamport_version,
                    changed_objects,
                    unchanged_shared_objects,
                    auxiliary_data_digest,
                })
            } else {
                let BinaryTransactionEffectsV1 {
                    status,
                    epoch,
                    gas_used,
                    transaction_digest,
                    gas_object_index,
                    events_digest,
                    dependencies,
                    lamport_version,
                    changed_objects,
                    unchanged_shared_objects,
                    auxiliary_data_digest,
                } = Deserialize::deserialize(deserializer)?;
                Ok(Self {
                    status,
                    epoch,
                    gas_used,
                    transaction_digest,
                    gas_object_index,
                    events_digest,
                    dependencies,
                    lamport_version,
                    changed_objects,
                    unchanged_shared_objects,
                    auxiliary_data_digest,
                })
            }
        }
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum ReadableUnchangedSharedKind {
        ReadOnlyRoot {
            #[serde(with = "crate::_serde::ReadableDisplay")]
            version: Version,
            digest: Digest,
        },
        MutateDeleted {
            #[serde(with = "crate::_serde::ReadableDisplay")]
            version: Version,
        },
        ReadDeleted {
            #[serde(with = "crate::_serde::ReadableDisplay")]
            version: Version,
        },
        Cancelled {
            #[serde(with = "crate::_serde::ReadableDisplay")]
            version: Version,
        },
        PerEpochConfig,
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    enum BinaryUnchangedSharedKind {
        ReadOnlyRoot { version: Version, digest: Digest },
        MutateDeleted { version: Version },
        ReadDeleted { version: Version },
        Cancelled { version: Version },
        PerEpochConfig,
    }

    impl Serialize for UnchangedSharedKind {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = match self.clone() {
                    UnchangedSharedKind::ReadOnlyRoot { version, digest } => {
                        ReadableUnchangedSharedKind::ReadOnlyRoot { version, digest }
                    }
                    UnchangedSharedKind::MutateDeleted { version } => {
                        ReadableUnchangedSharedKind::MutateDeleted { version }
                    }
                    UnchangedSharedKind::ReadDeleted { version } => {
                        ReadableUnchangedSharedKind::ReadDeleted { version }
                    }
                    UnchangedSharedKind::Cancelled { version } => {
                        ReadableUnchangedSharedKind::Cancelled { version }
                    }
                    UnchangedSharedKind::PerEpochConfig => {
                        ReadableUnchangedSharedKind::PerEpochConfig
                    }
                };
                readable.serialize(serializer)
            } else {
                let binary = match self.clone() {
                    UnchangedSharedKind::ReadOnlyRoot { version, digest } => {
                        BinaryUnchangedSharedKind::ReadOnlyRoot { version, digest }
                    }
                    UnchangedSharedKind::MutateDeleted { version } => {
                        BinaryUnchangedSharedKind::MutateDeleted { version }
                    }
                    UnchangedSharedKind::ReadDeleted { version } => {
                        BinaryUnchangedSharedKind::ReadDeleted { version }
                    }
                    UnchangedSharedKind::Cancelled { version } => {
                        BinaryUnchangedSharedKind::Cancelled { version }
                    }
                    UnchangedSharedKind::PerEpochConfig => {
                        BinaryUnchangedSharedKind::PerEpochConfig
                    }
                };
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for UnchangedSharedKind {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                ReadableUnchangedSharedKind::deserialize(deserializer).map(
                    |readable| match readable {
                        ReadableUnchangedSharedKind::ReadOnlyRoot { version, digest } => {
                            Self::ReadOnlyRoot { version, digest }
                        }
                        ReadableUnchangedSharedKind::MutateDeleted { version } => {
                            Self::MutateDeleted { version }
                        }
                        ReadableUnchangedSharedKind::ReadDeleted { version } => {
                            Self::ReadDeleted { version }
                        }
                        ReadableUnchangedSharedKind::Cancelled { version } => {
                            Self::Cancelled { version }
                        }
                        ReadableUnchangedSharedKind::PerEpochConfig => Self::PerEpochConfig,
                    },
                )
            } else {
                BinaryUnchangedSharedKind::deserialize(deserializer).map(|binary| match binary {
                    BinaryUnchangedSharedKind::ReadOnlyRoot { version, digest } => {
                        Self::ReadOnlyRoot { version, digest }
                    }
                    BinaryUnchangedSharedKind::MutateDeleted { version } => {
                        Self::MutateDeleted { version }
                    }
                    BinaryUnchangedSharedKind::ReadDeleted { version } => {
                        Self::ReadDeleted { version }
                    }
                    BinaryUnchangedSharedKind::Cancelled { version } => Self::Cancelled { version },
                    BinaryUnchangedSharedKind::PerEpochConfig => Self::PerEpochConfig,
                })
            }
        }
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(tag = "state", rename_all = "snake_case")]
    enum ReadableObjectIn {
        Missing,
        Data {
            #[serde(with = "crate::_serde::ReadableDisplay")]
            version: Version,
            digest: Digest,
            owner: Owner,
        },
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    enum BinaryObjectIn {
        Missing,
        Data {
            version: Version,
            digest: Digest,
            owner: Owner,
        },
    }

    impl Serialize for ObjectIn {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = match self.clone() {
                    ObjectIn::Missing => ReadableObjectIn::Missing,
                    ObjectIn::Data {
                        version,
                        digest,
                        owner,
                    } => ReadableObjectIn::Data {
                        version,
                        digest,
                        owner,
                    },
                };
                readable.serialize(serializer)
            } else {
                let binary = match self.clone() {
                    ObjectIn::Missing => BinaryObjectIn::Missing,
                    ObjectIn::Data {
                        version,
                        digest,
                        owner,
                    } => BinaryObjectIn::Data {
                        version,
                        digest,
                        owner,
                    },
                };
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for ObjectIn {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                ReadableObjectIn::deserialize(deserializer).map(|readable| match readable {
                    ReadableObjectIn::Missing => Self::Missing,
                    ReadableObjectIn::Data {
                        version,
                        digest,
                        owner,
                    } => Self::Data {
                        version,
                        digest,
                        owner,
                    },
                })
            } else {
                BinaryObjectIn::deserialize(deserializer).map(|binary| match binary {
                    BinaryObjectIn::Missing => Self::Missing,
                    BinaryObjectIn::Data {
                        version,
                        digest,
                        owner,
                    } => Self::Data {
                        version,
                        digest,
                        owner,
                    },
                })
            }
        }
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(tag = "state", rename_all = "snake_case")]
    enum ReadableObjectOut {
        Missing,
        ObjectWrite {
            digest: Digest,
            owner: Owner,
        },
        PackageWrite {
            #[serde(with = "crate::_serde::ReadableDisplay")]
            version: Version,
            digest: Digest,
        },
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    enum BinaryObjectOut {
        Missing,
        ObjectWrite {
            digest: Digest,
            owner: Owner,
        },
        PackageWrite {
            #[serde(with = "crate::_serde::ReadableDisplay")]
            version: Version,
            digest: Digest,
        },
    }

    impl Serialize for ObjectOut {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = match self.clone() {
                    ObjectOut::Missing => ReadableObjectOut::Missing,
                    ObjectOut::ObjectWrite { digest, owner } => {
                        ReadableObjectOut::ObjectWrite { digest, owner }
                    }
                    ObjectOut::PackageWrite { version, digest } => {
                        ReadableObjectOut::PackageWrite { version, digest }
                    }
                };
                readable.serialize(serializer)
            } else {
                let binary = match self.clone() {
                    ObjectOut::Missing => BinaryObjectOut::Missing,
                    ObjectOut::ObjectWrite { digest, owner } => {
                        BinaryObjectOut::ObjectWrite { digest, owner }
                    }
                    ObjectOut::PackageWrite { version, digest } => {
                        BinaryObjectOut::PackageWrite { version, digest }
                    }
                };
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for ObjectOut {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                ReadableObjectOut::deserialize(deserializer).map(|readable| match readable {
                    ReadableObjectOut::Missing => Self::Missing,
                    ReadableObjectOut::ObjectWrite { digest, owner } => {
                        Self::ObjectWrite { digest, owner }
                    }
                    ReadableObjectOut::PackageWrite { version, digest } => {
                        Self::PackageWrite { version, digest }
                    }
                })
            } else {
                BinaryObjectOut::deserialize(deserializer).map(|binary| match binary {
                    BinaryObjectOut::Missing => Self::Missing,
                    BinaryObjectOut::ObjectWrite { digest, owner } => {
                        Self::ObjectWrite { digest, owner }
                    }
                    BinaryObjectOut::PackageWrite { version, digest } => {
                        Self::PackageWrite { version, digest }
                    }
                })
            }
        }
    }
}
