// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// ===========================================================================
// Coin(s) Queries
// ===========================================================================

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "CoinMetadataArgs")]
pub struct CoinMetadataQuery {
    #[arguments(coinType: $coin_type)]
    pub coin_metadata: Option<CoinMetadata>,
}

// ===========================================================================
// Coin(s) Query Args
// ===========================================================================

#[derive(cynic::QueryVariables, Debug)]
pub struct CoinMetadataArgs<'a> {
    pub coin_type: &'a str,
}

// ===========================================================================
// Types
// ===========================================================================

use crate::query_types::{BigInt, schema};

/// The coin metadata associated with the given coin type.
#[derive(cynic::QueryFragment, Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cynic(schema = "rpc", graphql_type = "CoinMetadata")]
pub struct CoinMetadata {
    /// The number of decimal places used to represent the token.
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub decimals: Option<i32>,
    /// Optional description of the token, provided by the creator of the token.
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub description: Option<String>,
    /// Icon URL of the coin.
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub icon_url: Option<String>,
    /// Full, official name of the token.
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub name: Option<String>,
    /// The token's identifying abbreviation.
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub symbol: Option<String>,
    /// The overall quantity of tokens that will be issued.
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub supply: Option<BigInt>,
    /// Version of the token.
    pub version: u64,
}
