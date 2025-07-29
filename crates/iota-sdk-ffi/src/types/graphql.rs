// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_graphql_client::query_types::{ObjectRef, TransactionBlockKindInput};

use crate::types::{
    address::Address,
    transaction::{SignedTransaction, TransactionEffects},
};

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct TransactionMetadata(pub iota_graphql_client::query_types::TransactionMetadata);

#[uniffi::export]
impl TransactionMetadata {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self(Default::default())
    }

    pub fn gas_budget(&self, gas_budget: u64) -> Self {
        let Self(mut inner) = self.clone();
        inner.gas_budget = Some(gas_budget);
        Self(inner)
    }

    pub fn gas_objects(&self, gas_objects: Vec<ObjectRef>) -> Self {
        let Self(mut inner) = self.clone();
        inner.gas_objects = Some(gas_objects);
        Self(inner)
    }

    pub fn gas_price(&self, gas_price: u64) -> Self {
        let Self(mut inner) = self.clone();
        inner.gas_price = Some(gas_price);
        Self(inner)
    }

    pub fn gas_sponsor(&self, gas_sponsor: &Address) -> Self {
        let Self(mut inner) = self.clone();
        inner.gas_sponsor = Some(**gas_sponsor);
        Self(inner)
    }

    pub fn sender(&self, sender: &Address) -> Self {
        let Self(mut inner) = self.clone();
        inner.sender = Some(**sender);
        Self(inner)
    }
}

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct TransactionDataEffects(pub iota_graphql_client::TransactionDataEffects);

#[uniffi::export]
impl TransactionDataEffects {
    #[uniffi::constructor]
    pub fn new(tx: &SignedTransaction, effects: &TransactionEffects) -> Self {
        Self(iota_graphql_client::TransactionDataEffects {
            tx: tx.0.clone(),
            effects: effects.0.clone(),
        })
    }

    pub fn tx(&self) -> SignedTransaction {
        self.0.tx.clone().into()
    }

    pub fn effects(&self) -> TransactionEffects {
        self.0.effects.clone().into()
    }
}

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct TransactionsFilter(pub iota_graphql_client::query_types::TransactionsFilter);

#[uniffi::export]
impl TransactionsFilter {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self(Default::default())
    }

    pub fn function(&self, function: String) -> Self {
        let Self(mut inner) = self.clone();
        inner.function = Some(function);
        Self(inner)
    }

    pub fn kind(&self, kind: TransactionBlockKindInput) -> Self {
        let Self(mut inner) = self.clone();
        inner.kind = Some(kind);
        Self(inner)
    }

    pub fn after_checkpoint(&self, after_checkpoint: u64) -> Self {
        let Self(mut inner) = self.clone();
        inner.after_checkpoint = Some(after_checkpoint);
        Self(inner)
    }

    pub fn at_checkpoint(&self, at_checkpoint: u64) -> Self {
        let Self(mut inner) = self.clone();
        inner.at_checkpoint = Some(at_checkpoint);
        Self(inner)
    }

    pub fn before_checkpoint(&self, before_checkpoint: u64) -> Self {
        let Self(mut inner) = self.clone();
        inner.before_checkpoint = Some(before_checkpoint);
        Self(inner)
    }

    pub fn affected_address(&self, affected_address: &Address) -> Self {
        let Self(mut inner) = self.clone();
        inner.affected_address = Some(**affected_address);
        Self(inner)
    }

    pub fn sent_address(&self, sent_address: &Address) -> Self {
        let Self(mut inner) = self.clone();
        inner.sent_address = Some(**sent_address);
        Self(inner)
    }

    pub fn input_object(&self, input_object: &Address) -> Self {
        let Self(mut inner) = self.clone();
        inner.input_object = Some(**input_object);
        Self(inner)
    }

    pub fn changed_object(&self, changed_object: &Address) -> Self {
        let Self(mut inner) = self.clone();
        inner.changed_object = Some(**changed_object);
        Self(inner)
    }

    pub fn transaction_ids(&self, transaction_ids: Vec<String>) -> Self {
        let Self(mut inner) = self.clone();
        inner.transaction_ids = Some(transaction_ids);
        Self(inner)
    }
}

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct DryRunResult(pub iota_graphql_client::DryRunResult);

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct TransactionEvent(pub iota_graphql_client::TransactionEvent);
