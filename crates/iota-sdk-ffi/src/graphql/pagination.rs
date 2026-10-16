// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    graphql::query_types::{
        GraphQLDynamicFieldOutput, GraphQLEpoch, GraphQLEvent, GraphQLPageInfo,
        GraphQLTransactionDataEffects, GraphQLValidator,
    },
    types::{
        checkpoint::CheckpointSummary,
        coin::Coin,
        iota_names::NameRegistration,
        object::{MovePackage, Object},
        transaction::{SignedTransaction, TransactionEffects},
    },
};

macro_rules! define_paged_record {
    ($id:ident, $type_:ty) => {
        /// A page of items returned by the GraphQL server.
        #[derive(uniffi::Record)]
        pub struct $id {
            /// Information about the page, such as the cursor and whether there are
            /// more pages.
            pub page_info: GraphQLPageInfo,
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

define_paged_record!(GraphQLSignedTransactionPage, SignedTransaction);
define_paged_record!(
    GraphQLTransactionDataEffectsPage,
    GraphQLTransactionDataEffects
);
define_paged_record!(GraphQLDynamicFieldOutputPage, GraphQLDynamicFieldOutput);
define_paged_record!(GraphQLEventPage, GraphQLEvent);
define_paged_record!(GraphQLEpochPage, GraphQLEpoch);
define_paged_record!(GraphQLValidatorPage, GraphQLValidator);

macro_rules! define_paged_object {
    ($id:ident, $type_:ty) => {
        /// A page of items returned by the GraphQL server.
        #[derive(uniffi::Record)]
        pub struct $id {
            /// Information about the page, such as the cursor and whether there are
            /// more pages.
            pub page_info: GraphQLPageInfo,
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

define_paged_object!(GraphQLCoinPage, Coin);
define_paged_object!(GraphQLObjectPage, Object);
define_paged_object!(GraphQLTransactionEffectsPage, TransactionEffects);
define_paged_object!(GraphQLMovePackagePage, MovePackage);
define_paged_object!(GraphQLCheckpointSummaryPage, CheckpointSummary);
define_paged_object!(GraphQLNameRegistrationPage, NameRegistration);
