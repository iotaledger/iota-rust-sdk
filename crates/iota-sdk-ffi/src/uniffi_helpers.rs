// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::graphql_client::query_types::{Base64, BigInt, PageInfo};
use serde_json::Value;

use crate::types::{
    checkpoint::CheckpointSummary,
    coin::Coin,
    events::Event,
    graphql::{DynamicFieldOutput, Epoch, TransactionDataEffects, Validator},
    iota_names::NameRegistration,
    object::{MovePackage, Object},
    transaction::{SignedTransaction, TransactionEffects},
};

macro_rules! define_paged_record {
    ($id:ident, $type_:ty) => {
        /// A page of items returned by the GraphQL server.
        #[derive(uniffi::Record)]
        pub struct $id {
            /// Information about the page, such as the cursor and whether there are
            /// more pages.
            pub page_info: PageInfo,
            /// The data returned by the server.
            pub data: Vec<$type_>,
        }

        impl From<iota_sdk::graphql_client::pagination::Page<$type_>> for $id {
            fn from(value: iota_sdk::graphql_client::pagination::Page<$type_>) -> Self {
                Self {
                    page_info: value.page_info.into(),
                    data: value.data,
                }
            }
        }
    };
}

define_paged_record!(SignedTransactionPage, SignedTransaction);
define_paged_record!(TransactionDataEffectsPage, TransactionDataEffects);
define_paged_record!(DynamicFieldOutputPage, DynamicFieldOutput);
define_paged_record!(EventPage, Event);
define_paged_record!(EpochPage, Epoch);
define_paged_record!(ValidatorPage, Validator);

macro_rules! define_paged_object {
    ($id:ident, $type_:ty) => {
        /// A page of items returned by the GraphQL server.
        #[derive(uniffi::Record)]
        pub struct $id {
            /// Information about the page, such as the cursor and whether there are
            /// more pages.
            pub page_info: PageInfo,
            /// The data returned by the server.
            pub data: Vec<std::sync::Arc<$type_>>,
        }

        impl From<iota_sdk::graphql_client::pagination::Page<$type_>> for $id {
            fn from(value: iota_sdk::graphql_client::pagination::Page<$type_>) -> Self {
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

define_paged_object!(CoinPage, Coin);
define_paged_object!(ObjectPage, Object);
define_paged_object!(TransactionEffectsPage, TransactionEffects);
define_paged_object!(MovePackagePage, MovePackage);
define_paged_object!(CheckpointSummaryPage, CheckpointSummary);
define_paged_object!(NameRegistrationPage, NameRegistration);

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

uniffi::custom_type!(BigInt, String, {
    remote,
    lower: |val| val.0,
    try_lift: |s| Ok(BigInt(s)),
});
