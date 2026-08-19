// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

pub mod api;
pub mod client;
pub mod faucet;
pub mod move_view_call_client;
pub mod output_types;
pub mod pagination;
pub mod query_types;
pub mod transaction_builder_client;

uniffi::custom_type!(Value, String, {
    remote,
    lower: |val| val.to_string(),
    try_lift: |s| Ok(serde_json::from_str(&s)?),
});
