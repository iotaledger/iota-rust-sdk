// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod v1;

pub use v1::{
    ChangedObject, ObjectIn, ObjectOut, TransactionEffectsV1, UnchangedSharedKind,
    UnchangedSharedObject,
};

use crate::{ObjectDigest, ObjectId, ObjectReference, ObjectVersion, Version};

/// The output or effects of executing a transaction
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// transaction-effects = %d00 transaction-effects-v1   ; V1
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
#[non_exhaustive]
pub enum TransactionEffects {
    V1(Box<TransactionEffectsV1>),
}

impl TransactionEffects {
    crate::def_is_as_into_opt!(V1(Box<TransactionEffectsV1>));
}

#[cfg(all(feature = "serde", test))]
mod tests {
    use base64ct::{Base64, Encoding};
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::{ObjectOut, TransactionEffects};

    // The files contain the bas64 encoded raw effects of transactions
    const GENESIS_EFFECTS: &str = include_str!("fixtures/genesis-transaction-effects");
    const SPONSOR_TX_EFFECTS: &str = include_str!("fixtures/sponsor-tx-effects");

    #[test]
    fn effects_fixtures() {
        for fixture in [GENESIS_EFFECTS, SPONSOR_TX_EFFECTS] {
            let fixture = Base64::decode_vec(fixture.trim()).unwrap();
            let fx: TransactionEffects = bcs::from_bytes(&fixture).unwrap();
            assert_eq!(bcs::to_bytes(&fx).unwrap(), fixture);

            let json = serde_json::to_string_pretty(&fx).unwrap();
            println!("{json}");
            assert_eq!(fx, serde_json::from_str(&json).unwrap());
        }
    }

    /// Shared inputs are drawn from both the objects a transaction changed and
    /// those it left unchanged, and a per-epoch config object is not one.
    #[test]
    fn input_shared_objects_span_changed_and_unchanged() {
        use crate::{
            ChangedObject, IdOperation, InputSharedObject, ObjectDigest, ObjectId, ObjectIn,
            ObjectOut, ObjectVersion, Owner, TransactionEffectsV1, UnchangedSharedKind,
            UnchangedSharedObject, Version,
        };

        let mutated = ObjectId::new([1; 32]);
        let read_only = ObjectId::new([2; 32]);
        let read_deleted = ObjectId::new([3; 32]);
        let mutate_deleted = ObjectId::new([4; 32]);
        let canceled = ObjectId::new([5; 32]);
        let per_epoch_config = ObjectId::new([6; 32]);
        let owned = ObjectId::new([7; 32]);
        let digest = ObjectDigest::new([8; 32]);
        let version = Version::from_u64(3);

        let shared_input = |object_id, owner| ChangedObject {
            object_id,
            input_state: ObjectIn::Data {
                version,
                digest,
                owner,
            },
            output_state: ObjectOut::ObjectWrite { digest, owner },
            id_operation: IdOperation::None,
        };
        let unchanged = |object_id, kind| UnchangedSharedObject { object_id, kind };

        let effects = TransactionEffectsV1 {
            status: crate::ExecutionStatus::Success,
            epoch: 0,
            gas_cost_summary: crate::GasCostSummary::default(),
            transaction_digest: crate::TransactionDigest::default(),
            gas_object_index: None,
            events_digest: None,
            dependencies: Vec::new(),
            lamport_version: Version::from_u64(4),
            changed_objects: vec![
                shared_input(mutated, Owner::Shared(version)),
                // An owned input is not a shared input.
                shared_input(owned, Owner::Address(crate::Address::ZERO)),
            ],
            unchanged_shared_objects: vec![
                unchanged(
                    read_only,
                    UnchangedSharedKind::ReadOnlyRoot { version, digest },
                ),
                unchanged(read_deleted, UnchangedSharedKind::ReadDeleted { version }),
                unchanged(
                    mutate_deleted,
                    UnchangedSharedKind::MutateDeleted { version },
                ),
                unchanged(canceled, UnchangedSharedKind::Canceled { version }),
                unchanged(per_epoch_config, UnchangedSharedKind::PerEpochConfig),
            ],
            auxiliary_data_digest: None,
        };

        let object = |object_id| ObjectVersion::new(object_id, version);
        assert_eq!(
            effects.input_shared_objects(),
            vec![
                InputSharedObject::Mutate(crate::ObjectReference::new(mutated, version, digest)),
                InputSharedObject::ReadOnly(crate::ObjectReference::new(
                    read_only, version, digest
                )),
                InputSharedObject::ReadDeleted(object(read_deleted)),
                InputSharedObject::MutateDeleted(object(mutate_deleted)),
                InputSharedObject::Canceled(object(canceled)),
            ],
        );

        // A shared object that no longer exists is reported with the tombstone
        // digest saying why.
        assert!(
            InputSharedObject::ReadDeleted(object(read_deleted))
                .object_reference()
                .digest
                .is_deleted()
        );
        assert_eq!(
            InputSharedObject::Canceled(object(canceled))
                .object_reference()
                .digest,
            ObjectDigest::OBJECT_CANCELED,
        );
    }

    /// A written object takes the version the transaction assigned, while a
    /// package keeps the version it was published or upgraded at. The fixtures
    /// cannot tell these apart, since they publish at their lamport version.
    #[test]
    fn object_changes_keep_a_package_at_its_own_version() {
        use crate::{
            ChangedObject, IdOperation, ObjectDigest, ObjectId, ObjectIn, ObjectOut, Owner,
            TransactionEffectsV1, Version,
        };

        let lamport_version = Version::from_u64(9);
        let package_version = Version::from_u64(7);
        let digest = ObjectDigest::new([1; 32]);
        let object = ObjectId::new([2; 32]);
        let package = ObjectId::new([3; 32]);

        let effects = TransactionEffectsV1 {
            status: crate::ExecutionStatus::Success,
            epoch: 0,
            gas_cost_summary: crate::GasCostSummary::default(),
            transaction_digest: crate::TransactionDigest::default(),
            gas_object_index: None,
            events_digest: None,
            dependencies: Vec::new(),
            lamport_version,
            changed_objects: vec![
                ChangedObject {
                    object_id: object,
                    input_state: ObjectIn::Missing,
                    output_state: ObjectOut::ObjectWrite {
                        digest,
                        owner: Owner::Address(crate::Address::ZERO),
                    },
                    id_operation: IdOperation::Created,
                },
                ChangedObject {
                    object_id: package,
                    input_state: ObjectIn::Missing,
                    output_state: ObjectOut::PackageWrite {
                        version: package_version,
                        digest,
                    },
                    id_operation: IdOperation::Created,
                },
            ],
            unchanged_shared_objects: Vec::new(),
            auxiliary_data_digest: None,
        };

        let changes = effects.object_changes();
        assert_eq!(changes[0].output_version, Some(lamport_version));
        assert_eq!(changes[1].output_version, Some(package_version));

        // The same distinction reaches the object sets.
        assert_eq!(
            effects
                .created()
                .into_iter()
                .map(|owned| owned.reference.version)
                .collect::<Vec<_>>(),
            vec![lamport_version, package_version],
        );
    }

    /// Each changed object is reported once, with the version and digest of
    /// whichever sides it existed on.
    #[test]
    fn object_changes_resolve_each_side() {
        for fixture in [GENESIS_EFFECTS, SPONSOR_TX_EFFECTS] {
            let effects: TransactionEffects =
                bcs::from_bytes(&Base64::decode_vec(fixture.trim()).unwrap()).unwrap();
            let fx = effects.as_v1();

            let changes = fx.object_changes();
            assert_eq!(changes.len(), fx.changed_objects.len());

            for (change, changed) in changes.iter().zip(&fx.changed_objects) {
                assert_eq!(change.object_id, changed.object_id);
                assert_eq!(change.id_operation, changed.id_operation);
                assert_eq!(change.input_version, changed.input_state.version_opt());
                assert_eq!(change.input_digest, changed.input_state.digest_opt());
                assert_eq!(
                    change.input_version.is_some(),
                    change.input_digest.is_some()
                );
                assert_eq!(
                    change.output_version.is_some(),
                    change.output_digest.is_some()
                );

                // A written object takes the version this transaction assigned;
                // a package keeps the version it was published or upgraded at.
                match changed.output_state {
                    ObjectOut::ObjectWrite { digest, .. } => {
                        assert_eq!(change.output_version, Some(fx.lamport_version));
                        assert_eq!(change.output_digest, Some(digest));
                    }
                    ObjectOut::PackageWrite { version, digest } => {
                        assert_eq!(change.output_version, Some(version));
                        assert_eq!(change.output_digest, Some(digest));
                    }
                    _ => assert_eq!(change.output_version, None),
                }
            }
        }
    }

    /// A package write is only ever a create or a mutate: it is not reported as
    /// an unwrap, and never as the gas object.
    #[test]
    fn a_package_write_is_neither_unwrapped_nor_gas() {
        use crate::{
            ChangedObject, IdOperation, ObjectDigest, ObjectId, ObjectIn, ObjectOut,
            TransactionEffectsV1, Version,
        };

        let package = ObjectId::new([1; 32]);
        let effects = TransactionEffectsV1 {
            status: crate::ExecutionStatus::Success,
            epoch: 0,
            gas_cost_summary: crate::GasCostSummary::default(),
            transaction_digest: crate::TransactionDigest::default(),
            // The one entry stands in as the gas object, which it cannot be.
            gas_object_index: Some(0),
            events_digest: None,
            dependencies: Vec::new(),
            lamport_version: Version::from_u64(2),
            changed_objects: vec![ChangedObject {
                object_id: package,
                input_state: ObjectIn::Missing,
                output_state: ObjectOut::PackageWrite {
                    version: Version::from_u64(1),
                    digest: ObjectDigest::new([2; 32]),
                },
                // Neither created nor deleted, which is what would otherwise
                // read as an unwrap.
                id_operation: IdOperation::None,
            }],
            unchanged_shared_objects: Vec::new(),
            auxiliary_data_digest: None,
        };

        assert!(effects.unwrapped().is_empty());
        assert!(effects.gas_object().is_none());
    }

    /// The tagged unions are exactly the sets they are drawn from, so nothing
    /// is dropped or double-counted, and each object carries the right tag.
    #[test]
    fn tagged_unions_cover_the_object_sets() {
        use crate::{ObjectRemoveKind, WriteKind};

        for fixture in [GENESIS_EFFECTS, SPONSOR_TX_EFFECTS] {
            let effects: TransactionEffects =
                bcs::from_bytes(&Base64::decode_vec(fixture.trim()).unwrap()).unwrap();
            let fx = effects.as_v1();

            let changed = fx.all_changed_objects();
            assert_eq!(
                changed.len(),
                fx.mutated().len() + fx.created().len() + fx.unwrapped().len()
            );
            assert!(!changed.is_empty(), "the fixture must change objects");
            let of_kind = |kind| {
                changed
                    .iter()
                    .filter(|(_, k)| *k == kind)
                    .map(|(object, _)| *object)
                    .collect::<Vec<_>>()
            };
            assert_eq!(of_kind(WriteKind::Mutate), fx.mutated());
            assert_eq!(of_kind(WriteKind::Create), fx.created());
            assert_eq!(of_kind(WriteKind::Unwrap), fx.unwrapped());

            let removed = fx.all_removed_objects();
            assert_eq!(removed.len(), fx.deleted().len() + fx.wrapped().len());
            let removed_of_kind = |kind| {
                removed
                    .iter()
                    .filter(|(_, k)| *k == kind)
                    .map(|(reference, _)| *reference)
                    .collect::<Vec<_>>()
            };
            assert_eq!(removed_of_kind(ObjectRemoveKind::Delete), fx.deleted());
            assert_eq!(removed_of_kind(ObjectRemoveKind::Wrap), fx.wrapped());

            // An object unwrapped and then deleted was never in the store, so it
            // is not a removal.
            for reference in fx.unwrapped_then_deleted() {
                assert!(!removed.iter().any(|(removed, _)| *removed == reference));
            }
        }
    }

    /// Every changed object falls into exactly one of the reported sets, so the
    /// sets partition `changed_objects` and never report an object twice.
    #[test]
    fn object_sets_partition_the_changed_objects() {
        for fixture in [GENESIS_EFFECTS, SPONSOR_TX_EFFECTS] {
            let effects: TransactionEffects =
                bcs::from_bytes(&Base64::decode_vec(fixture.trim()).unwrap()).unwrap();
            let fx = effects.as_v1();

            let owned = fx
                .created()
                .into_iter()
                .chain(fx.mutated())
                .chain(fx.unwrapped())
                .map(|owned| owned.reference.object_id);
            let removed = fx
                .deleted()
                .into_iter()
                .chain(fx.unwrapped_then_deleted())
                .chain(fx.wrapped())
                .map(|object_ref| object_ref.object_id);
            let reported: Vec<_> = owned.chain(removed).collect();

            assert!(!reported.is_empty(), "the fixture must change objects");
            let unique: std::collections::BTreeSet<_> = reported.iter().collect();
            assert_eq!(unique.len(), reported.len(), "an object was reported twice");
            assert_eq!(
                unique,
                fx.changed_objects
                    .iter()
                    .map(|changed| &changed.object_id)
                    .collect(),
            );
        }
    }

    /// Output objects other than packages are reported at the lamport version,
    /// and the objects reported as modified are exactly those with a
    /// pre-transaction state.
    #[test]
    fn object_sets_agree_with_the_raw_effects() {
        for fixture in [GENESIS_EFFECTS, SPONSOR_TX_EFFECTS] {
            let effects: TransactionEffects =
                bcs::from_bytes(&Base64::decode_vec(fixture.trim()).unwrap()).unwrap();
            let fx = effects.as_v1();

            for object_ref in fx.deleted().into_iter().chain(fx.unwrapped_then_deleted()) {
                assert!(object_ref.digest.is_deleted());
                assert_eq!(object_ref.version, fx.lamport_version);
            }
            for object_ref in fx.wrapped() {
                assert!(object_ref.digest.is_wrapped());
            }

            let modified: Vec<_> = fx
                .modified_at_versions()
                .into_iter()
                .map(|modified| modified.object_id)
                .collect();
            let old_metadata: Vec<_> = fx
                .old_object_metadata()
                .into_iter()
                .map(|owned| owned.reference.object_id)
                .collect();
            assert_eq!(modified, old_metadata);
        }
    }

    /// A transaction that pays for itself reports its gas object; the genesis
    /// transaction requires no gas and reports none.
    #[test]
    fn gas_object_is_absent_without_a_gas_payment() {
        let effects: TransactionEffects =
            bcs::from_bytes(&Base64::decode_vec(SPONSOR_TX_EFFECTS.trim()).unwrap()).unwrap();
        let sponsored = effects.as_v1();
        let gas = sponsored.gas_object().expect("a sponsored tx pays gas");
        assert_eq!(gas.reference.version, sponsored.lamport_version);
        assert!(
            sponsored
                .mutated()
                .iter()
                .any(|owned| owned.reference == gas.reference),
            "the gas object is reported as mutated"
        );

        let genesis: TransactionEffects =
            bcs::from_bytes(&Base64::decode_vec(GENESIS_EFFECTS.trim()).unwrap()).unwrap();
        assert!(genesis.as_v1().gas_object().is_none());
    }
}

impl crate::TreeDisplay for TransactionEffects {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.enum_name("Transaction Effects");
        match self {
            Self::V1(v1) => v1.fmt_tree(w),
        }
    }
}

/// A shared object an executed transaction took as input.
///
/// Not a wire type: this is the effects' view of the shared objects a
/// transaction was sequenced against, drawn from both the objects it changed
/// and those it left unchanged.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum InputSharedObject {
    /// Taken mutably, and written back by the transaction.
    Mutate(ObjectReference),
    /// Read without being mutated.
    ReadOnly(ObjectReference),
    /// Read, but already deleted by an earlier transaction.
    ReadDeleted(ObjectVersion),
    /// Taken mutably, but already deleted by an earlier transaction.
    MutateDeleted(ObjectVersion),
    /// Taken by a transaction that consensus canceled; the version carries the
    /// cancellation reason.
    Canceled(ObjectVersion),
}

impl InputSharedObject {
    /// The object's reference. A shared object that no longer exists is
    /// reported at the version it was last known at, with the tombstone digest
    /// for why it is gone.
    pub fn object_reference(&self) -> ObjectReference {
        match self {
            Self::Mutate(reference) | Self::ReadOnly(reference) => *reference,
            Self::ReadDeleted(object) | Self::MutateDeleted(object) => ObjectReference::new(
                object.object_id,
                object.version,
                ObjectDigest::OBJECT_DELETED,
            ),
            Self::Canceled(object) => ObjectReference::new(
                object.object_id,
                object.version,
                ObjectDigest::OBJECT_CANCELED,
            ),
        }
    }
}

impl crate::TreeDisplay for InputSharedObject {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Input Shared Object")?;
        let kind = match self {
            Self::Mutate(_) => "Mutate",
            Self::ReadOnly(_) => "Read Only",
            Self::ReadDeleted(_) => "Read Deleted",
            Self::MutateDeleted(_) => "Mutate Deleted",
            Self::Canceled(_) => "Canceled",
        };
        w.leaf("Kind", &kind, false)?;
        w.child("Reference", &self.object_reference(), true)
    }
}

/// How an object came to be in the store after a transaction wrote it.
///
/// Not a wire type: this tags an object reported by
/// [`TransactionEffectsV1::all_changed_objects`] with which of the object sets
/// it came from.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WriteKind {
    /// The object existed already and the transaction changed its contents.
    Mutate,
    /// The transaction created the object.
    Create,
    /// The object was wrapped inside another object, and the transaction
    /// restored it to the store.
    Unwrap,
}

impl std::fmt::Display for WriteKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Mutate => "Mutate",
            Self::Create => "Create",
            Self::Unwrap => "Unwrap",
        };
        f.write_str(text)
    }
}

/// Why an object is no longer in the store after a transaction.
///
/// Not a wire type: this tags an object reported by
/// [`TransactionEffectsV1::all_removed_objects`] with which of the object sets
/// it came from.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ObjectRemoveKind {
    /// The transaction deleted the object.
    Delete,
    /// The transaction wrapped the object inside another one.
    Wrap,
}

impl std::fmt::Display for ObjectRemoveKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Delete => "Delete",
            Self::Wrap => "Wrap",
        };
        f.write_str(text)
    }
}

/// What an executed transaction did to one object, with the version and digest
/// each side is at resolved.
///
/// Not a wire type: this is [`ChangedObject`] with the versions filled in,
/// since a written object's version is the transaction's rather than one the
/// entry carries. A `None` version means the object did not exist on that side.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectChange {
    /// The object's id.
    pub object_id: ObjectId,
    /// The version the object was at before the transaction, if it existed.
    pub input_version: Option<Version>,
    /// The digest the object had before the transaction, if it existed.
    pub input_digest: Option<ObjectDigest>,
    /// The version the object is at after the transaction, if it still exists.
    pub output_version: Option<Version>,
    /// The digest the object has after the transaction, if it still exists.
    pub output_digest: Option<ObjectDigest>,
    /// Whether the transaction created or deleted the object's id.
    pub id_operation: IdOperation,
}

impl crate::TreeDisplay for ObjectChange {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Object Change")?;
        w.leaf("Object ID", &self.object_id, false)?;
        w.option_leaf("Input Version", &self.input_version, false)?;
        w.option_leaf("Input Digest", &self.input_digest, false)?;
        w.option_leaf("Output Version", &self.output_version, false)?;
        w.option_leaf("Output Digest", &self.output_digest, false)?;
        w.leaf("ID Operation", &self.id_operation, true)
    }
}

crate::impl_tree_display!(TransactionEffects, InputSharedObject, ObjectChange);

/// Defines what happened to an ObjectId during execution
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// id-operation = %d00   ; None
///              / %d01   ; Created
///              / %d02   ; Deleted
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, strum::Display)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "lowercase")
)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
#[non_exhaustive]
pub enum IdOperation {
    None,
    Created,
    Deleted,
}

impl IdOperation {
    crate::def_is!(None, Created, Deleted);
}
