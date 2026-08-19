// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod v1;

pub use v1::{
    ChangedObject, ObjectIn, ObjectOut, TransactionEffectsV1, UnchangedSharedKind,
    UnchangedSharedObject,
};

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

    use super::TransactionEffects;

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
                .map(|(object_id, _)| object_id)
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

crate::impl_tree_display!(TransactionEffects);

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
