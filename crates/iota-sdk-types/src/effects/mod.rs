// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod v1;

pub use v1::{
    ChangedObject, IdOperation, ObjectIn, ObjectOut, TransactionEffectsV1, UnchangedSharedKind,
    UnchangedSharedObject,
};

use crate::{SignedTransaction, TypeTag, execution_status::ExecutionStatus};

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

/// The result of a simulation (dry run), which includes the effects of the
/// transaction and intermediate results for each command.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DryRunResult {
    /// The error that occurred during dry run execution, if any.
    pub error: Option<String>,
    /// The intermediate results for each command of the dry run execution,
    /// including contents of mutated references and return values.
    pub results: Vec<DryRunEffect>,
    /// The transaction block representing the dry run execution.
    pub transaction: Option<SignedTransaction>,
    /// The effects of the transaction execution.
    pub effects: Option<TransactionEffects>,
}

/// Effects of a single command in the dry run, including mutated references
/// and return values.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DryRunEffect {
    /// Changes made to arguments that were mutably borrowed by this
    /// command.
    pub mutated_references: Vec<DryRunMutation>,
    /// Return results of this command.
    pub return_values: Vec<DryRunReturn>,
}

/// A mutation to an argument that was mutably borrowed by a command.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DryRunMutation {
    /// The transaction argument that was mutated.
    pub input: TransactionArgument,
    /// The Move type of the mutated value.
    pub type_tag: TypeTag,
    /// The BCS representation of the mutated value.
    pub bcs: Vec<u8>,
}

/// A return value from a command in the dry run.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DryRunReturn {
    /// The Move type of the return value.
    pub type_tag: TypeTag,
    /// The BCS representation of the return value.
    pub bcs: Vec<u8>,
}

/// A transaction argument used in programmable transactions.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TransactionArgument {
    /// Reference to the gas coin.
    GasCoin,
    /// An input to the programmable transaction block.
    Input {
        /// Index of the programmable transaction block input (0-indexed).
        ix: u32,
    },
    /// The result of another transaction command.
    Result {
        /// The index of the previous command (0-indexed) that returned this
        /// result.
        cmd: u32,
        /// If the previous command returns multiple values, this is the
        /// index of the individual result among the multiple
        /// results from that command (also 0-indexed).
        ix: Option<u32>,
    },
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
