// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Query types for IOTA coin balances.

use crate::{
    Address,
    query_types::{BigInt, schema},
};

// ===========================================================================
// Queries
// ===========================================================================

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "BalanceQueryArgs")]
pub struct BalanceQuery {
    #[arguments(address: $address)]
    pub owner: Option<Owner>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Owner", variables = "BalanceQueryArgs")]
pub struct Owner {
    #[arguments(type: $coin_type)]
    pub balance: Option<Balance>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Balance")]
pub struct Balance {
    pub total_balance: Option<BigInt>,
}

// ===========================================================================
// Query Args
// ===========================================================================

#[derive(cynic::QueryVariables, Debug)]
pub struct BalanceQueryArgs {
    pub address: Address,
    pub coin_type: Option<String>,
}
