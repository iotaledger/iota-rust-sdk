// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

pub mod api;
pub mod client;
pub mod client_methods;
pub mod faucet;
pub mod output_types;
pub mod pagination;
pub mod query_types;

uniffi::custom_type!(Value, String, {
    remote,
    lower: |val| val.to_string(),
    try_lift: |s| Ok(serde_json::from_str(&s)?),
});
