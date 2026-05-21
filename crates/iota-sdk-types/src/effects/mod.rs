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
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
#[non_exhaustive]
pub enum TransactionEffects {
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
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::{TransactionEffects, TransactionEffectsV1};

    #[derive(serde::Serialize)]
    #[serde(tag = "version")]
    #[serde(rename = "TransactionEffects")]
    enum ReadableTransactionEffectsRef<'a> {
        #[serde(rename = "1")]
        V1(&'a TransactionEffectsV1),
    }

    #[derive(serde::Deserialize)]
    #[serde(tag = "version")]
    #[serde(rename = "TransactionEffects")]
    pub enum ReadableTransactionEffects {
        #[serde(rename = "1")]
        V1(Box<TransactionEffectsV1>),
    }

    #[derive(serde::Serialize)]
    #[serde(rename = "TransactionEffects")]
    enum BinaryTransactionEffectsRef<'a> {
        V1(&'a TransactionEffectsV1),
    }

    #[derive(serde::Deserialize)]
    #[serde(rename = "TransactionEffects")]
    pub enum BinaryTransactionEffects {
        V1(Box<TransactionEffectsV1>),
    }

    impl Serialize for TransactionEffects {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = match self {
                    TransactionEffects::V1(fx) => ReadableTransactionEffectsRef::V1(fx),
                };
                readable.serialize(serializer)
            } else {
                let binary = match self {
                    TransactionEffects::V1(fx) => BinaryTransactionEffectsRef::V1(fx),
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
                ReadableTransactionEffects::deserialize(deserializer)
                    .map(|readable| match readable {
                        ReadableTransactionEffects::V1(fx) => Self::V1(fx),
                    })
            } else {
                BinaryTransactionEffects::deserialize(deserializer).map(|binary| match binary {
                    BinaryTransactionEffects::V1(fx) => Self::V1(fx),
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
