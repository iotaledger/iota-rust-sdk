// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::GasCostSummary;

#[uniffi::remote(Record)]
pub struct GasCostSummary {
    pub computation_cost: u64,
    pub computation_cost_burned: u64,
    pub storage_cost: u64,
    pub storage_rebate: u64,
    pub non_refundable_storage_fee: u64,
}
