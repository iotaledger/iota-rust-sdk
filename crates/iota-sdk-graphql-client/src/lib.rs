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
mod streams;
mod subscription;
mod tls;
mod transaction_builder_client;
mod wait;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod test_utils;

// Re-export types used by query_types module internally
#[cfg(feature = "move-types")]
pub use api::move_objects::{ListMoveObjectsQuery, MoveObjectFilter, OwnedMoveObject};
pub use api::{
    balance::GetBalanceQuery,
    checkpoints::{
        GetCheckpointQuery, GetLatestCheckpointSequenceNumberQuery, GetTotalTransactionBlocksQuery,
        ListCheckpointsQuery,
    },
    coins::{GetCoinMetadataQuery, GetTotalSupplyQuery, ListCoinsQuery, ListGasCoinsQuery},
    dry_run::{DryRunTransactionKindQuery, DryRunTransactionQuery},
    dynamic_fields::{GetDynamicFieldQuery, GetDynamicObjectFieldQuery, ListDynamicFieldsQuery},
    epochs::{GetEpochQuery, GetEpochTotalCheckpointsQuery, GetEpochTotalTransactionBlocksQuery},
    events::ListEventsQuery,
    iota_names::{
        GetIotaNamesDefaultNameQuery, GetIotaNamesLookupQuery, ListIotaNamesRegistrationsQuery,
    },
    move_view_call::{MoveViewArg, MoveViewArgList, MoveViewCallJsonQuery, MoveViewCallQuery},
    network::{
        GetChainIdQuery, GetProtocolConfigQuery, GetReferenceGasPriceQuery,
        ListActiveValidatorsQuery,
    },
    objects::{
        GetMoveObjectContentsBcsQuery, GetMoveObjectContentsQuery, GetObjectBcsQuery,
        GetObjectQuery, ListObjectsQuery,
    },
    package::{
        GetNormalizedMoveFunctionQuery, GetNormalizedMoveModuleQuery, GetPackageLatestQuery,
        GetPackageQuery, ListPackageVersionsQuery, ListPackagesQuery,
    },
    transactions::{
        ExecuteTransactionQuery, GetTransactionDataEffectsQuery, GetTransactionEffectsQuery,
        GetTransactionQuery, IsTransactionFinalizedQuery, IsTransactionIndexedOnNodeQuery,
        ListAddressTransactionsQuery, ListTransactionsDataEffectsQuery,
        ListTransactionsEffectsQuery, ListTransactionsQuery, WaitForTransactionQuery,
    },
};
pub use client::{GetMaxPageSizeQuery, GraphQLClient, GraphQLClientBuilder, USER_AGENT};
pub use cynic;
pub use error::{GraphQLError, GraphQLResult};
pub use iota_transaction_builder::WaitForTransaction;
pub use iota_types;
pub(crate) use iota_types::Address;
pub use output_types::*;
pub use pagination::{Direction, Page, PaginationFilter};
pub use reqwest;
pub use streams::PageStream;
pub use subscription::{EventsSubscriptionBuilder, TransactionsSubscriptionBuilder};

mod base64 {
    use base64ct::Encoding;

    use crate::error::{GraphQLError, GraphQLResult};

    /// Decodes a base64 string from a response into bytes.
    pub(crate) fn decode(input: &str) -> GraphQLResult<Vec<u8>> {
        base64ct::Base64::decode_vec(input).map_err(|e| GraphQLError::Parse(e.into()))
    }
}
