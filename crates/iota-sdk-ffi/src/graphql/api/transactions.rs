// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Transactions API implementation.

use std::{sync::Arc, time::Duration};

use crate::{
    error::Result,
    graphql::{
        client::GraphQLClient,
        pagination::{SignedTransactionPage, TransactionDataEffectsPage, TransactionEffectsPage},
        query_types::{
            AddressTransactionRelationship, PaginationFilter, TransactionDataEffects,
            TransactionsFilter,
        },
    },
    transaction_builder::WaitForTransaction,
    types::{
        address::Address,
        digest::TransactionDigest,
        signature::UserSignature,
        transaction::{SignedTransaction, Transaction, TransactionEffects},
    },
};

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl GraphQLClient {
    /// Get a transaction by its digest.
    pub async fn transaction(
        &self,
        digest: &TransactionDigest,
    ) -> Result<Option<SignedTransaction>> {
        Ok(self
            .0
            .read()
            .await
            .transaction(**digest)
            .await?
            .map(Into::into))
    }

    /// Get transactions by their digests, including transactions that are not
    /// checkpointed yet. The result has one entry per requested digest, in the
    /// same order; a digest that was not found is `None`.
    pub async fn transactions_by_digest(
        &self,
        digests: Vec<Arc<TransactionDigest>>,
    ) -> Result<Vec<Option<SignedTransaction>>> {
        let digests = digests.into_iter().map(|d| **d).collect::<Vec<_>>();
        let transactions = self
            .0
            .read()
            .await
            .transactions_by_digest(digests.iter().copied())
            .await?;

        // Cloned rather than removed so a digest listed twice resolves twice.
        Ok(digests
            .iter()
            .map(|digest| transactions.get(digest).cloned().map(Into::into))
            .collect())
    }

    /// Get a transaction's effects by its digest.
    pub async fn transaction_effects(
        &self,
        digest: &TransactionDigest,
    ) -> Result<Option<Arc<TransactionEffects>>> {
        Ok(self
            .0
            .read()
            .await
            .transaction_effects(**digest)
            .await?
            .map(Into::into)
            .map(Arc::new))
    }

    /// Get a transaction's data and effects by its digest.
    pub async fn transaction_data_effects(
        &self,
        digest: &TransactionDigest,
    ) -> Result<Option<TransactionDataEffects>> {
        Ok(self
            .0
            .read()
            .await
            .transaction_data_effects(**digest)
            .await?
            .map(Into::into))
    }

    /// Get a page of transactions based on the provided filters.
    #[uniffi::method(default(pagination_filter = None, filter = None))]
    pub async fn transactions(
        &self,
        filter: Option<Arc<TransactionsFilter>>,
        pagination_filter: Option<PaginationFilter>,
    ) -> Result<SignedTransactionPage> {
        Ok(self
            .0
            .read()
            .await
            .transactions(
                filter.as_deref().map(Into::into),
                pagination_filter.map(Into::into).unwrap_or_default(),
            )
            .await?
            .map(Into::into)
            .into())
    }

    /// Get a page of transactions related to the given address.
    /// `relation` selects how the address relates to them, defaulting to the
    /// transactions it sent.
    #[uniffi::method(default(relation = None, filter = None, pagination_filter = None))]
    pub async fn address_transactions(
        &self,
        address: &Address,
        relation: Option<AddressTransactionRelationship>,
        filter: Option<Arc<TransactionsFilter>>,
        pagination_filter: Option<PaginationFilter>,
    ) -> Result<SignedTransactionPage> {
        Ok(self
            .0
            .read()
            .await
            .address_transactions(
                **address,
                relation.map(Into::into),
                filter.as_deref().map(Into::into),
                pagination_filter.map(Into::into).unwrap_or_default(),
            )
            .await?
            .map(Into::into)
            .into())
    }

    /// Get a page of transactions' effects based on the provided filters.
    #[uniffi::method(default(pagination_filter = None, filter = None))]
    pub async fn transactions_effects(
        &self,
        filter: Option<Arc<TransactionsFilter>>,
        pagination_filter: Option<PaginationFilter>,
    ) -> Result<TransactionEffectsPage> {
        Ok(self
            .0
            .read()
            .await
            .transactions_effects(
                filter.as_deref().map(Into::into),
                pagination_filter.map(Into::into).unwrap_or_default(),
            )
            .await?
            .map(Into::into)
            .into())
    }

    /// Get a page of transactions' data and effects based on the provided
    /// filters.
    #[uniffi::method(default(pagination_filter = None, filter = None))]
    pub async fn transactions_data_effects(
        &self,
        filter: Option<Arc<TransactionsFilter>>,
        pagination_filter: Option<PaginationFilter>,
    ) -> Result<TransactionDataEffectsPage> {
        Ok(self
            .0
            .read()
            .await
            .transactions_data_effects(
                filter.as_deref().map(Into::into),
                pagination_filter.map(Into::into).unwrap_or_default(),
            )
            .await?
            .map(Into::into)
            .into())
    }

    /// Execute a transaction.
    #[uniffi::method(default(wait_for = None))]
    pub async fn execute_transaction(
        &self,
        signatures: Vec<Arc<UserSignature>>,
        transaction: &Transaction,
        wait_for: Option<WaitForTransaction>,
    ) -> Result<TransactionEffects> {
        Ok(self
            .0
            .read()
            .await
            .execute_transaction(
                &signatures
                    .into_iter()
                    .map(|s| s.0.clone())
                    .collect::<Vec<_>>(),
                &transaction.0,
                wait_for.map(Into::into),
            )
            .await?
            .into())
    }

    /// Returns whether the transaction for the given digest has been indexed
    /// on the node. This means that it can be queried by its digest and its
    /// effects will be usable for subsequent transactions. To check for
    /// full finalization, use `is_transaction_finalized`.
    #[uniffi::method]
    pub async fn is_transaction_indexed_on_node(&self, digest: &TransactionDigest) -> Result<bool> {
        Ok(self
            .0
            .read()
            .await
            .is_transaction_indexed_on_node(**digest)
            .await?)
    }

    /// Returns whether the transaction for the given digest has been included
    /// in a checkpoint (finalized).
    #[uniffi::method]
    pub async fn is_transaction_finalized(&self, digest: &TransactionDigest) -> Result<bool> {
        Ok(self
            .0
            .read()
            .await
            .is_transaction_finalized(**digest)
            .await?)
    }

    /// Wait for the indexing (on the node, not the indexer) or finalization of
    /// a transaction by its digest. An optional timeout can be provided,
    /// which, if exceeded, will return an error (default 60s).
    #[uniffi::method(default(timeout = None))]
    pub async fn wait_for_transaction(
        &self,
        digest: &TransactionDigest,
        wait_for: WaitForTransaction,
        timeout: Option<Duration>,
    ) -> Result<()> {
        Ok(self
            .0
            .read()
            .await
            .wait_for_transaction(**digest, wait_for.into(), timeout)
            .await?)
    }
}
