// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types from the Move standard library (system package `0x1`).

/// Rust version of the Move `std::fixed_point32::FixedPoint32` type.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FixedPoint32 {
    pub value: u64,
}
