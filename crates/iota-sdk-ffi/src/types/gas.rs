// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct GasCostSummary(pub iota_types::GasCostSummary);

#[uniffi::export]
impl GasCostSummary {
    #[uniffi::constructor]
    pub fn new(
        computation_cost: u64,
        computation_cost_burned: u64,
        storage_cost: u64,
        storage_rebate: u64,
        non_refundable_storage_fee: u64,
    ) -> Self {
        Self(iota_types::GasCostSummary {
            computation_cost,
            computation_cost_burned,
            storage_cost,
            storage_rebate,
            non_refundable_storage_fee,
        })
    }

    pub fn computation_cost(&self) -> u64 {
        self.0.computation_cost
    }

    pub fn computation_cost_burned(&self) -> u64 {
        self.0.computation_cost_burned
    }

    pub fn storage_cost(&self) -> u64 {
        self.0.storage_cost
    }

    pub fn storage_rebate(&self) -> u64 {
        self.0.storage_rebate
    }

    pub fn non_refundable_storage_fee(&self) -> u64 {
        self.0.non_refundable_storage_fee
    }
}
