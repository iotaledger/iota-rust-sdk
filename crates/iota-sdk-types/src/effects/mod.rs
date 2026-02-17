// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod v1;

pub use v1::{
    ChangedObject, IdOperation, ObjectIn, ObjectOut, TransactionEffectsV1, UnchangedSharedKind,
    UnchangedSharedObject,
};

use crate::execution_status::ExecutionStatus;

/// The output or effects of executing a transaction
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// transaction-effects =  %x00 effects-v1
///                     =/ %x01 effects-v2
/// ```
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(
    feature = "schemars",
    derive(schemars::JsonSchema),
    schemars(tag = "version")
)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[non_exhaustive]
pub enum TransactionEffects {
    #[cfg_attr(feature = "schemars", schemars(rename = "1"))]
    V1(Box<TransactionEffectsV1>),
}

impl TransactionEffects {
    crate::def_is!(V1);

    pub fn as_v1(&self) -> &TransactionEffectsV1 {
        let Self::V1(effects) = self;
        effects
    }

    pub fn into_v1(self) -> TransactionEffectsV1 {
        let Self::V1(effects) = self;
        *effects
    }

    /// Return the status of the transaction.
    pub fn status(&self) -> &ExecutionStatus {
        match self {
            TransactionEffects::V1(e) => e.status(),
        }
    }

    /// Return the epoch in which this transaction was executed.
    pub fn epoch(&self) -> u64 {
        match self {
            TransactionEffects::V1(e) => e.epoch(),
        }
    }

    /// Return the gas cost summary of the transaction.
    pub fn gas_summary(&self) -> &crate::gas::GasCostSummary {
        match self {
            TransactionEffects::V1(e) => e.gas_summary(),
        }
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::{TransactionEffects, TransactionEffectsV1};

    #[derive(serde::Serialize)]
    #[serde(tag = "version")]
    enum ReadableEffectsRef<'a> {
        #[serde(rename = "1")]
        V1(&'a TransactionEffectsV1),
    }

    #[derive(serde::Deserialize)]
    #[serde(tag = "version")]
    pub enum ReadableEffects {
        #[serde(rename = "1")]
        V1(Box<TransactionEffectsV1>),
    }

    #[derive(serde::Serialize)]
    enum BinaryEffectsRef<'a> {
        V1(&'a TransactionEffectsV1),
    }

    #[derive(serde::Deserialize)]
    pub enum BinaryEffects {
        V1(Box<TransactionEffectsV1>),
    }

    impl Serialize for TransactionEffects {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = match self {
                    TransactionEffects::V1(fx) => ReadableEffectsRef::V1(fx),
                };
                readable.serialize(serializer)
            } else {
                let binary = match self {
                    TransactionEffects::V1(fx) => BinaryEffectsRef::V1(fx),
                };
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for TransactionEffects {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                ReadableEffects::deserialize(deserializer).map(|readable| match readable {
                    ReadableEffects::V1(fx) => Self::V1(fx),
                })
            } else {
                BinaryEffects::deserialize(deserializer).map(|binary| match binary {
                    BinaryEffects::V1(fx) => Self::V1(fx),
                })
            }
        }
    }

    #[cfg(test)]
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
    }
}

#[cfg(test)]
mod tests_accessors {
    use super::*;
    use crate::{
        Digest, GasCostSummary,
        execution_status::ExecutionStatus,
    };

    fn create_v1_effects() -> TransactionEffectsV1 {
        TransactionEffectsV1 {
            status: ExecutionStatus::Success,
            epoch: 10,
            gas_used: GasCostSummary {
                computation_cost: 100,
                computation_cost_burned: 50,
                storage_cost: 200,
                storage_rebate: 50,
                non_refundable_storage_fee: 10,
            },
            transaction_digest: Digest::new([1; 32]),
            gas_object_index: Some(0),
            events_digest: None,
            dependencies: vec![],
            lamport_version: 5,
            changed_objects: vec![],
            unchanged_shared_objects: vec![],
            auxiliary_data_digest: None,
        }
    }

    #[test]
    fn test_accessors() {
        let v1 = create_v1_effects();
        let effects = TransactionEffects::V1(Box::new(v1.clone()));

        assert_eq!(effects.status(), &ExecutionStatus::Success);
        assert_eq!(effects.epoch(), 10);
        
        let gas = effects.gas_summary();
        assert_eq!(gas.computation_cost, 100);
        assert_eq!(gas.storage_cost, 200);

        // Test as_v1
        let v1_ref = effects.as_v1();
        assert_eq!(v1_ref.epoch, 10);

        // Test into_v1
        let v1_owned = effects.into_v1();
        assert_eq!(v1_owned.epoch, 10);
        assert_eq!(v1_owned, v1);
    }
}
