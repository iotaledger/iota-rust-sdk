// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

mod api;
mod client;
pub mod error;
pub mod faucet;
pub mod output_types;
pub mod pagination;
pub mod query_types;
pub mod streams;
#[cfg(not(target_arch = "wasm32"))]
mod subscription;
mod transaction_builder_client;
mod wait;

#[cfg(test)]
mod test_utils;

// Re-export types used by query_types module internally
pub use client::Client;
pub use iota_transaction_builder::WaitForTransaction;
pub(crate) use iota_types::Address;
pub use output_types::*;
pub use pagination::{Direction, Page, PaginationFilter};
