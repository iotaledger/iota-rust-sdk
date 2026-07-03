// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// Summary of gas charges.
///
/// Storage is charged independently of computation.
/// There are 3 parts to the storage charges:
/// - `storage_cost`: it is the charge of storage at the time the transaction is
///   executed. The cost of storage is the number of bytes of the objects being
///   mutated multiplied by a variable storage cost per byte
/// - `storage_rebate`: this is the amount a user gets back when manipulating an
///   object. The `storage_rebate` is the `storage_cost` for an object minus
///   fees.
/// - `non_refundable_storage_fee`: not all the value of the object storage cost
///   is given back to user and there is a small fraction that is kept by the
///   system. This value tracks that charge.
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
/// gas-cost-summary = u64   ; computation-cost
///                    u64   ; computation-cost-burned
///                    u64   ; storage-cost
///                    u64   ; storage-rebate
///                    u64   ; non-refundable-storage-fee
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
pub struct GasCostSummary {
    /// Cost of computation/execution
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    pub computation_cost: u64,
    /// The burned component of the computation/execution costs
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    pub computation_cost_burned: u64,
    /// Storage cost, it's the sum of all storage cost for all objects created
    /// or mutated.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    pub storage_cost: u64,
    /// The amount of storage cost refunded to the user for all objects deleted
    /// or mutated in the transaction.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    pub storage_rebate: u64,
    /// The fee for the rebate. The portion of the storage rebate kept by the
    /// system.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
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
        self.computation_cost
            .checked_add(self.storage_cost)
            .expect("gas_used overflow")
    }

    /// The net gas usage, which is the total gas used minus the storage rebate.
    /// A positive number means used gas; negative number means refund.
    pub fn net_gas_usage(&self) -> i64 {
        (self.gas_used() as i64)
            .checked_sub(self.storage_rebate as i64)
            .expect("net_gas_usage underflow")
    }
}

impl std::ops::AddAssign<&Self> for GasCostSummary {
    fn add_assign(&mut self, other: &Self) {
        self.computation_cost = self
            .computation_cost
            .checked_add(other.computation_cost)
            .expect("computation_cost overflow");
        self.computation_cost_burned = self
            .computation_cost_burned
            .checked_add(other.computation_cost_burned)
            .expect("computation_cost_burned overflow");
        self.storage_cost = self
            .storage_cost
            .checked_add(other.storage_cost)
            .expect("storage_cost overflow");
        self.storage_rebate = self
            .storage_rebate
            .checked_add(other.storage_rebate)
            .expect("storage_rebate overflow");
        self.non_refundable_storage_fee = self
            .non_refundable_storage_fee
            .checked_add(other.non_refundable_storage_fee)
            .expect("non_refundable_storage_fee overflow");
    }
}

impl std::ops::SubAssign<&Self> for GasCostSummary {
    fn sub_assign(&mut self, other: &Self) {
        self.computation_cost = self
            .computation_cost
            .checked_sub(other.computation_cost)
            .expect("computation_cost underflow");
        self.computation_cost_burned = self
            .computation_cost_burned
            .checked_sub(other.computation_cost_burned)
            .expect("computation_cost_burned underflow");
        self.storage_cost = self
            .storage_cost
            .checked_sub(other.storage_cost)
            .expect("storage_cost underflow");
        self.storage_rebate = self
            .storage_rebate
            .checked_sub(other.storage_rebate)
            .expect("storage_rebate underflow");
        self.non_refundable_storage_fee = self
            .non_refundable_storage_fee
            .checked_sub(other.non_refundable_storage_fee)
            .expect("non_refundable_storage_fee underflow");
    }
}

impl std::ops::AddAssign<Self> for GasCostSummary {
    fn add_assign(&mut self, other: Self) {
        self.add_assign(&other);
    }
}

impl std::ops::SubAssign<Self> for GasCostSummary {
    fn sub_assign(&mut self, other: Self) {
        self.sub_assign(&other);
    }
}

impl crate::TreeDisplay for GasCostSummary {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Gas Cost Summary")?;
        w.leaf("Computation Cost", &self.computation_cost, false)?;
        w.leaf(
            "Computation Cost Burned",
            &self.computation_cost_burned,
            false,
        )?;
        w.leaf("Storage Cost", &self.storage_cost, false)?;
        w.leaf("Storage Rebate", &self.storage_rebate, false)?;
        w.leaf(
            "Non-Refundable Storage Fee",
            &self.non_refundable_storage_fee,
            true,
        )
    }
}

crate::impl_tree_display!(GasCostSummary);

#[cfg(all(test, feature = "serde"))]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    #[test]
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
}
