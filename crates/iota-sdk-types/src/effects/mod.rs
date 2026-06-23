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
    crate::def_is!(V1);

    /// Returns a shared reference to the V1 effects.
    pub fn as_v1(&self) -> &TransactionEffectsV1 {
        let Self::V1(effects) = self;
        effects
    }

    /// Returns a mutable reference to the V1 effects.
    pub fn as_mut_v1(&mut self) -> &mut TransactionEffectsV1 {
        let Self::V1(effects) = self;
        effects
    }

    /// Consumes the effects, returning the owned V1 effects.
    pub fn into_v1(self) -> TransactionEffectsV1 {
        let Self::V1(effects) = self;
        *effects
    }
}

#[cfg(all(feature = "serde", test))]
mod tests {
    use base64ct::{Base64, Encoding};
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::TransactionEffects;

    #[test]
    fn effects_fixtures() {
        // The files contain the bas64 encoded raw effects of transactions
        const GENESIS_EFFECTS: &str = include_str!("fixtures/genesis-transaction-effects");
        const SPONSOR_TX_EFFECTS: &str = include_str!("fixtures/sponsor-tx-effects");

        for fixture in [GENESIS_EFFECTS, SPONSOR_TX_EFFECTS] {
            let fixture = Base64::decode_vec(fixture.trim()).unwrap();
            let fx: TransactionEffects = bcs::from_bytes(&fixture).unwrap();
            assert_eq!(bcs::to_bytes(&fx).unwrap(), fixture);

            let json = serde_json::to_string_pretty(&fx).unwrap();
            println!("{json}");
            assert_eq!(fx, serde_json::from_str(&json).unwrap());
        }
    }

    #[test]
    fn as_mut_v1_mutates_in_place() {
        const SPONSOR_TX_EFFECTS: &str = include_str!("fixtures/sponsor-tx-effects");
        let fixture = Base64::decode_vec(SPONSOR_TX_EFFECTS.trim()).unwrap();
        let mut fx: TransactionEffects = bcs::from_bytes(&fixture).unwrap();

        let new_epoch = fx.as_v1().epoch + 1;
        fx.as_mut_v1().epoch = new_epoch;

        assert_eq!(fx.as_v1().epoch, new_epoch);
    }
}

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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
