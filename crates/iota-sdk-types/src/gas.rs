// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// Summary of gas charges.
///
/// Storage is charged independently of computation.
/// There are 3 parts to the storage charges:
/// `storage_cost`: it is the charge of storage at the time the transaction is
/// executed.                 The cost of storage is the number of bytes of the
/// objects being mutated                 multiplied by a variable storage cost
/// per byte `storage_rebate`: this is the amount a user gets back when
/// manipulating an object.                   The `storage_rebate` is the
/// `storage_cost` for an object minus fees. `non_refundable_storage_fee`: not
/// all the value of the object storage cost is                               
/// given back to user and there is a small fraction that                       
/// is kept by the system. This value tracks that charge.
///
/// When looking at a gas cost summary the amount charged to the user is
/// `computation_cost + storage_cost - storage_rebate`
/// and that is the amount that is deducted from the gas coins.
/// `non_refundable_storage_fee` is collected from the objects being
/// mutated/deleted and it is tracked by the system in storage funds.
///
/// Objects deleted, including the older versions of objects mutated, have the
/// storage field on the objects added up to a pool of "potential rebate". This
/// rebate then is reduced by the "nonrefundable rate" such that:
/// `potential_rebate(storage cost of deleted/mutated objects) =
/// storage_rebate + non_refundable_storage_fee`
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// gas-cost-summary = u64 ; computation-cost
///                    u64 ; storage-cost
///                    u64 ; storage-rebate
///                    u64 ; non-refundable-storage-fee
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct GasCostSummary {
    /// Cost of computation/execution
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub computation_cost: u64,
    /// The burned component of the computation/execution costs
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub computation_cost_burned: u64,
    /// Storage cost, it's the sum of all storage cost for all objects created
    /// or mutated.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub storage_cost: u64,
    /// The amount of storage cost refunded to the user for all objects deleted
    /// or mutated in the transaction.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub storage_rebate: u64,
    /// The fee for the rebate. The portion of the storage rebate kept by the
    /// system.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub non_refundable_storage_fee: u64,
}

impl GasCostSummary {
    /// Create a new gas cost summary.
    ///
    /// # Arguments
    /// * `computation_cost` - Cost of computation cost/execution.
    /// * `storage_cost` - Storage cost, it's the sum of all storage cost for
    ///   all objects created or mutated.
    /// * `storage_rebate` - The amount of storage cost refunded to the user for
    ///   all objects deleted or mutated in the transaction.
    /// * `non_refundable_storage_fee` - The fee for the rebate. The portion of
    ///   the storage rebate kept by the system.
    pub fn new(
        computation_cost: u64,
        computation_cost_burned: u64,
        storage_cost: u64,
        storage_rebate: u64,
        non_refundable_storage_fee: u64,
    ) -> GasCostSummary {
        GasCostSummary {
            computation_cost,
            computation_cost_burned,
            storage_cost,
            storage_rebate,
            non_refundable_storage_fee,
        }
    }

    /// The total gas used, which is the sum of computation and storage costs.
    pub fn gas_used(&self) -> u64 {
        self.computation_cost + self.storage_cost
    }

    /// The net gas usage, which is the total gas used minus the storage rebate.
    /// A positive number means used gas; negative number means refund.
    pub fn net_gas_usage(&self) -> i64 {
        self.gas_used() as i64 - self.storage_rebate as i64
    }
}

impl std::fmt::Display for GasCostSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "computation_cost: {}, ", self.computation_cost)?;
        write!(
            f,
            "computation_cost_burned: {}, ",
            self.computation_cost_burned
        )?;
        write!(f, "storage_cost: {}, ", self.storage_cost)?;
        write!(f, "storage_rebate: {}, ", self.storage_rebate)?;
        write!(
            f,
            "non_refundable_storage_fee: {}",
            self.non_refundable_storage_fee
        )
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    #[test]
    #[cfg(feature = "serde")]
    fn formats() {
        let actual = GasCostSummary {
            computation_cost: 42,
            computation_cost_burned: 24,
            storage_cost: u64::MAX,
            storage_rebate: 0,
            non_refundable_storage_fee: 9,
        };

        println!("{}", serde_json::to_string(&actual).unwrap());
        println!("{:?}", bcs::to_bytes(&actual).unwrap());
    }

    #[test]
    fn constructor_sets_all_fields() {
        let summary = GasCostSummary::new(100, 80, 50, 30, 10);
        assert_eq!(summary.computation_cost, 100);
        assert_eq!(summary.computation_cost_burned, 80);
        assert_eq!(summary.storage_cost, 50);
        assert_eq!(summary.storage_rebate, 30);
        assert_eq!(summary.non_refundable_storage_fee, 10);
    }

    #[test]
    fn gas_used_is_sum_of_computation_and_storage() {
        let summary = GasCostSummary::new(100, 80, 50, 30, 10);
        assert_eq!(summary.gas_used(), 150, "gas_used = computation + storage");
    }

    #[test]
    fn net_gas_usage_positive_when_cost_exceeds_rebate() {
        let summary = GasCostSummary::new(100, 80, 50, 30, 10);
        // 150 - 30 = 120
        assert_eq!(summary.net_gas_usage(), 120);
    }

    #[test]
    fn net_gas_usage_negative_when_rebate_exceeds_cost() {
        let summary = GasCostSummary::new(10, 5, 20, 100, 5);
        // (10+20) - 100 = -70
        assert_eq!(summary.net_gas_usage(), -70);
    }

    #[test]
    fn net_gas_usage_zero_when_balanced() {
        let summary = GasCostSummary::new(50, 30, 50, 100, 10);
        // (50+50) - 100 = 0
        assert_eq!(summary.net_gas_usage(), 0);
    }

    #[test]
    fn default_is_all_zeros() {
        let summary = GasCostSummary::default();
        assert_eq!(summary.computation_cost, 0);
        assert_eq!(summary.computation_cost_burned, 0);
        assert_eq!(summary.storage_cost, 0);
        assert_eq!(summary.storage_rebate, 0);
        assert_eq!(summary.non_refundable_storage_fee, 0);
        assert_eq!(summary.gas_used(), 0);
        assert_eq!(summary.net_gas_usage(), 0);
    }

    #[test]
    fn display_contains_all_field_names() {
        let summary = GasCostSummary::new(1, 2, 3, 4, 5);
        let display = summary.to_string();
        assert!(display.contains("computation_cost: 1"));
        assert!(display.contains("computation_cost_burned: 2"));
        assert!(display.contains("storage_cost: 3"));
        assert!(display.contains("storage_rebate: 4"));
        assert!(display.contains("non_refundable_storage_fee: 5"));
    }
}
