// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![cfg_attr(doc_cfg, feature(doc_cfg))]

mod api;
mod client;
pub mod error;
pub mod faucet;
mod move_view_call_client;
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
pub use api::move_objects::{ListMoveObjectsQuery, MoveObjectFilter, OwnedMoveObject};
pub use api::{
    balance::GetBalanceQuery,
    checkpoints::{GetCheckpointQuery, ListCheckpointsQuery},
    coins::{ListCoinsQuery, ListGasCoinsQuery},
    dry_run::{DryRunTransactionKindQuery, DryRunTransactionQuery},
    dynamic_fields::ListDynamicFieldsQuery,
    epochs::{GetEpochQuery, GetEpochTotalCheckpointsQuery, GetEpochTotalTransactionBlocksQuery},
    events::ListEventsQuery,
    iota_names::{GetIotaNamesDefaultNameQuery, ListIotaNamesRegistrationsQuery},
    move_view_call::{MoveViewCallJsonQuery, MoveViewCallQuery},
    network::{
        GetChainIdQuery, GetProtocolConfigQuery, GetReferenceGasPriceQuery,
        ListActiveValidatorsQuery,
    },
    objects::{
        GetMoveObjectContentsBcsQuery, GetMoveObjectContentsQuery, GetObjectQuery, ListObjectsQuery,
    },
    package::{
        GetNormalizedMoveFunctionQuery, GetNormalizedMoveModuleQuery, GetPackageQuery,
        ListPackageVersionsQuery, ListPackagesQuery,
    },
    transactions::{
        ExecuteTransactionQuery, ListAddressTransactionsQuery, ListTransactionsDataEffectsQuery,
        ListTransactionsEffectsQuery, ListTransactionsQuery, WaitForTransactionQuery,
    },
};
pub use client::{GraphQLClient, USER_AGENT};
pub use cynic;
pub use error::{GraphQLError, GraphQLResult};
pub use iota_transaction_builder::WaitForTransaction;
pub use iota_types;
pub(crate) use iota_types::Address;
pub use output_types::*;
pub use pagination::{Direction, Page, PaginationFilter};
pub use reqwest;
