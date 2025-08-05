// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_graphql_client::query_types::Base64;
use serde_json::Value;

use crate::types::{
    checkpoint::CheckpointSummary,
    coin::Coin,
    graphql::{DynamicFieldOutput, Epoch, Event, PageInfo, TransactionDataEffects, Validator},
    object::{MovePackage, Object},
    transaction::{SignedTransaction, TransactionEffects},
};

macro_rules! define_paged_record {
    ($id:ident, $typ:ty) => {
        /// A page of items returned by the GraphQL server.
        #[derive(Debug, Clone, uniffi::Record)]
        pub struct $id {
            /// Information about the page, such as the cursor and whether there are
            /// more pages.
            pub page_info: PageInfo,
            /// The data returned by the server.
            pub data: Vec<$typ>,
        }

        impl From<iota_graphql_client::pagination::Page<$typ>> for $id {
            fn from(value: iota_graphql_client::pagination::Page<$typ>) -> Self {
                Self {
                    page_info: value.page_info.into(),
                    data: value.data,
                }
            }
        }
    };
}

define_paged_record!(CheckpointSummaryPage, CheckpointSummary);
define_paged_record!(SignedTransactionPage, SignedTransaction);
define_paged_record!(TransactionDataEffectsPage, TransactionDataEffects);
define_paged_record!(DynamicFieldOutputPage, DynamicFieldOutput);
define_paged_record!(EventPage, Event);
define_paged_record!(ValidatorPage, Validator);

macro_rules! define_paged_object {
    ($id:ident, $typ:ty) => {
        /// A page of items returned by the GraphQL server.
        #[derive(Debug, Clone, uniffi::Record)]
        pub struct $id {
            /// Information about the page, such as the cursor and whether there are
            /// more pages.
            pub page_info: PageInfo,
            /// The data returned by the server.
            pub data: Vec<std::sync::Arc<$typ>>,
        }

        impl From<iota_graphql_client::pagination::Page<$typ>> for $id {
            fn from(value: iota_graphql_client::pagination::Page<$typ>) -> Self {
                Self {
                    page_info: value.page_info.into(),
                    data: value
                        .data
                        .into_iter()
                        .map(Into::into)
                        .map(std::sync::Arc::new)
                        .collect(),
                }
            }
        }
    };
}

define_paged_object!(EventPage, Event);
define_paged_object!(SignedTransactionPage, SignedTransaction);
define_paged_object!(TransactionDataEffectsPage, TransactionDataEffects);
define_paged_object!(CoinPage, Coin);
define_paged_object!(ObjectPage, Object);
define_paged_object!(TransactionEffectsPage, TransactionEffects);
define_paged_object!(MovePackagePage, MovePackage);
define_paged_object!(EpochPage, Epoch);

uniffi::custom_type!(Value, String, {
    remote,
    lower: |val| val.to_string(),
    try_lift: |s| Ok(serde_json::from_str(&s)?),
});

uniffi::custom_type!(Base64, String, {
    remote,
    lower: |val| val.0,
    try_lift: |s| Ok(Base64(s)),
});
