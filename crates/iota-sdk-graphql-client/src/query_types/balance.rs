// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    Address,
    query_types::{BigInt, schema},
};

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "BalanceArgs")]
pub(crate) struct BalanceQueryFragment {
    #[arguments(address: $address)]
    pub owner: Option<Owner>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Owner", variables = "BalanceArgs")]
pub(crate) struct Owner {
    #[arguments(type: $coin_type)]
    pub balance: Option<Balance>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Balance")]
pub(crate) struct Balance {
    pub total_balance: Option<BigInt>,
}

#[derive(cynic::QueryVariables, Debug)]
pub(crate) struct BalanceArgs {
    pub address: Address,
    pub coin_type: Option<String>,
}
