// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// Register IOTA RPC schema for creating structs for queries
fn main() {
    iota_graphql_client_build::register_schema("rpc");
}
