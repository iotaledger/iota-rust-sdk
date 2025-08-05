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
#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Serialize, serde_derive::Deserialize)
)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum TransactionEffects {
    #[cfg_attr(feature = "schemars", schemars(rename = "1"))]
    V1(Box<TransactionEffectsV1>),
}

#[cfg(feature = "uniffi")]
pub type BoxedTransactionEffectsV1 = Box<TransactionEffectsV1>;

#[cfg(feature = "uniffi")]
uniffi::custom_type!(BoxedTransactionEffectsV1, TransactionEffectsV1, {
    lower: |btt| *btt,
    try_lift: |tt| Ok(Box::new(tt)),
});

impl TransactionEffects {
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
