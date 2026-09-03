// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Transactions API implementation.

use std::{sync::Arc, time::Duration};

use crate::{
    error::Result,
    graphql::{
        client::GraphQLClient,
        pagination::{SignedTransactionPage, TransactionDataEffectsPage, TransactionEffectsPage},
        query_types::{PaginationFilter, TransactionDataEffects, TransactionsFilter},
    },
    types::{
        digest::TransactionDigest,
        signature::UserSignature,
        transaction::{SignedTransaction, Transaction, TransactionEffects},
    },
};

/// Determines what to wait for after executing a transaction.
///
/// Users should almost always use WaitForTransaction::Finalized (the default).
/// The GraphQL client interacts with the indexer, not the fullnode directly.
/// Using WaitForTransaction::IndexedOnNode only guarantees the transaction is
/// indexed on the fullnode (meaning you can submit transactions that reference
/// objects created by this transaction), but subsequent queries using the
/// transaction ID can still fail until the transaction is indexed on the
/// indexer.
#[derive(uniffi::Enum)]
pub enum WaitForTransaction {
    /// Indicates that the transaction effects will be usable in subsequent
    /// transactions (you can reference objects created by this transaction),
    /// and that the transaction itself is indexed on the fullnode.
    ///
    /// **Warning:** This does not guarantee the transaction is indexed on the
    /// indexer. Since the GraphQL client queries the indexer, subsequent
    /// queries with this transaction ID may still fail. Prefer
    /// WaitForTransaction::Finalized unless you have a specific reason to use
    /// this.
    IndexedOnNode,
    /// Indicates that the transaction has been included in a checkpoint, and
    /// all queries may include it.
    Finalized,
}

impl From<WaitForTransaction> for iota_sdk::graphql_client::WaitForTransaction {
    fn from(value: WaitForTransaction) -> Self {
        match value {
            WaitForTransaction::IndexedOnNode => Self::IndexedOnNode,
            WaitForTransaction::Finalized => Self::Finalized,
        }
    }
}

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
