// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_graphql_client::pagination::Page;
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
        #[derive(uniffi::Object, derive_more::From)]
        pub struct $id(Page<$typ>);

        #[uniffi::export]
        impl $id {
            pub fn page_info(&self) -> PageInfo {
                self.0.page_info().clone().into()
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

define_paged_record!(CheckpointSummaryPage, CheckpointSummary);
define_paged_record!(SignedTransactionPage, SignedTransaction);
define_paged_record!(TransactionDataEffectsPage, TransactionDataEffects);

macro_rules! define_paged_object {
    ($id:ident, $typ:ty) => {
        #[derive(uniffi::Object, derive_more::From)]
        pub struct $id(Page<$typ>);

        #[uniffi::export]
        impl $id {
            pub fn page_info(&self) -> PageInfo {
                self.0.page_info().clone().into()
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

define_paged_object!(EventPage, Event);
define_paged_object!(CoinPage, Coin);
define_paged_object!(ObjectPage, Object);
define_paged_object!(TransactionEffectsPage, TransactionEffects);
define_paged_object!(MovePackagePage, MovePackage);
define_paged_object!(ValidatorPage, Validator);
define_paged_object!(EpochPage, Epoch);
define_paged_object!(DynamicFieldOutputPage, DynamicFieldOutput);

uniffi::custom_type!(Value, String, {
    remote,
    lower: |val| val.to_string(),
    try_lift: |s| Ok(serde_json::from_str(&s)?),
});
