// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![cfg_attr(doc_cfg, feature(doc_cfg))]

mod api;
mod client;
pub mod error;
pub mod faucet;
pub mod output_types;
pub mod pagination;
pub mod query_types;
pub mod streams;
mod subscription;
mod tls;
mod transaction_builder_client;
mod wait;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod test_utils;

// Re-export types used by query_types module internally
#[cfg(feature = "move-types")]
pub use api::move_objects::{MoveObjectFilter, OwnedMoveObject};
pub use api::move_view_call::{MoveViewArg, MoveViewArgList};
pub use client::{GraphQLClient, USER_AGENT};
pub use cynic;
pub use error::{GraphQLError, GraphQLResult};
pub use iota_transaction_builder::WaitForTransaction;
pub use iota_types;
pub(crate) use iota_types::Address;
pub use output_types::*;
pub use pagination::{Direction, Page, PaginationFilter};
pub use reqwest;
