// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::{
    CheckpointSummary, MovePackage, Object, SignedTransaction, TransactionEffects, framework::Coin,
};

use crate::{
    Page, TransactionDataEffects, TransactionEvent,
    query_types::{Epoch, PageInfo, Validator},
};

macro_rules! define_paged {
    ($id:ident, $typ:ty) => {
        pub type $id = Page<$typ>;

        #[uniffi::remote(Record)]
        pub struct $id {
            page_info: PageInfo,
            data: Vec<$typ>,
        }
    };
}

define_paged!(MovePackagePage, MovePackage);
define_paged!(ValidatorPage, Validator);
define_paged!(CoinPage, Coin);
define_paged!(CheckpointSummaryPage, CheckpointSummary);
define_paged!(EpochPage, Epoch);
define_paged!(TransactionEventPage, TransactionEvent);
define_paged!(ObjectPage, Object);
define_paged!(SignedTransactionPage, SignedTransaction);
define_paged!(TransactionEffectsPage, TransactionEffects);
define_paged!(TransactionDataEffectsPage, TransactionDataEffects);
