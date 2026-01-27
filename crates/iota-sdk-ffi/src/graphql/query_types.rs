// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::graphql_client::query_types::{Base64, BigInt};

uniffi::custom_type!(Base64, String, {
    remote,
    lower: |val| val.0,
    try_lift: |s| Ok(Base64(s)),
});

uniffi::custom_type!(BigInt, String, {
    remote,
    lower: |val| val.0,
    try_lift: |s| Ok(BigInt(s)),
});
