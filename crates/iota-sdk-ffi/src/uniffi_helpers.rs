// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_graphql_client::{
    DynamicFieldOutput, TransactionEvent,
    pagination::Page,
    query_types::{Epoch, PageInfo, Validator},
};
use iota_types::{CheckpointSummary, MovePackage, Object, TransactionEffects, framework::Coin};
use serde_json::Value;

use crate::types::{graphql::TransactionDataEffects, transaction::SignedTransaction};

macro_rules! define_paged_record {
    ($id:ident, $typ:ty) => {
        #[derive(uniffi::Object, derive_more::From)]
        pub struct $id(Page<$typ>);

        #[uniffi::export]
        impl $id {
            pub fn page_info(&self) -> PageInfo {
                self.0.page_info().clone()
            }

            pub fn data(&self) -> Vec<$typ> {
                self.0.data().to_vec()
            }

            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }
    };
}

define_paged_record!(ValidatorPage, Validator);
define_paged_record!(CheckpointSummaryPage, CheckpointSummary);
define_paged_record!(EpochPage, Epoch);
define_paged_record!(TransactionEffectsPage, TransactionEffects);
define_paged_record!(MovePackagePage, MovePackage);
define_paged_record!(ObjectPage, Object);
define_paged_record!(DynamicFieldOutputPage, DynamicFieldOutput);
define_paged_record!(TransactionEventPage, TransactionEvent);
define_paged_record!(CoinPage, Coin);

macro_rules! define_paged_object {
    ($id:ident, $typ:ty) => {
        #[derive(uniffi::Object, derive_more::From)]
        pub struct $id(Page<$typ>);

        #[uniffi::export]
        impl $id {
            pub fn page_info(&self) -> PageInfo {
                self.0.page_info().clone()
            }

            pub fn data(&self) -> Vec<std::sync::Arc<$typ>> {
                self.0
                    .data()
                    .iter()
                    .cloned()
                    .map(std::sync::Arc::new)
                    .collect()
            }

            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }
    };
}

define_paged_object!(SignedTransactionPage, SignedTransaction);
define_paged_object!(TransactionDataEffectsPage, TransactionDataEffects);

uniffi::custom_type!(Value, String, {
    remote,
    lower: |val| val.to_string(),
    try_lift: |s| Ok(serde_json::from_str(&s)?),
});
