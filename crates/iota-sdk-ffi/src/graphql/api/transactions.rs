// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Transactions API implementation.

use std::{sync::Arc, time::Duration};

use iota_sdk::graphql_client::{WaitForTx, pagination::PaginationFilter};

use crate::{
    error::Result,
    graphql::{
        client::GraphQLClient,
        pagination::{SignedTransactionPage, TransactionDataEffectsPage, TransactionEffectsPage},
        query_types::{TransactionDataEffects, TransactionsFilter},
    },
    types::{
        digest::Digest,
        signature::UserSignature,
        transaction::{SignedTransaction, Transaction, TransactionEffects},
    },
};

/// Determines what to wait for after executing a transaction.
#[uniffi::remote(Enum)]
#[non_exhaustive]
pub enum WaitForTx {
    /// Indicates that the transaction effects will be usable in subsequent
    /// transactions, and that the transaction itself is indexed on the node.
    Indexed,
    /// Indicates that the transaction has been included in a checkpoint, and
    /// all queries may include it.
    Finalized,
}

#[uniffi::export(async_runtime = "tokio")]
impl GraphQLClient {
    // ===========================================================================
    // Transaction API
    // ===========================================================================

    /// Get a transaction by its digest.
    pub async fn transaction(&self, digest: &Digest) -> Result<Option<SignedTransaction>> {
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
        digest: &Digest,
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
        digest: &Digest,
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
        filter: Option<TransactionsFilter>,
        pagination_filter: Option<PaginationFilter>,
    ) -> Result<SignedTransactionPage> {
        Ok(self
            .0
            .read()
            .await
            .transactions(
                filter.map(Into::into),
                pagination_filter.unwrap_or_default(),
            )
            .await?
            .map(Into::into)
            .into())
    }

    /// Get a page of transactions' effects based on the provided filters.
    #[uniffi::method(default(pagination_filter = None, filter = None))]
    pub async fn transactions_effects(
        &self,
        filter: Option<TransactionsFilter>,
        pagination_filter: Option<PaginationFilter>,
    ) -> Result<TransactionEffectsPage> {
        Ok(self
            .0
            .read()
            .await
            .transactions_effects(
                filter.map(Into::into),
                pagination_filter.unwrap_or_default(),
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
        filter: Option<TransactionsFilter>,
        pagination_filter: Option<PaginationFilter>,
    ) -> Result<TransactionDataEffectsPage> {
        Ok(self
            .0
            .read()
            .await
            .transactions_data_effects(
                filter.map(Into::into),
                pagination_filter.unwrap_or_default(),
            )
            .await?
            .map(Into::into)
            .into())
    }

    /// Execute a transaction.
    #[uniffi::method(default(wait_for = None))]
    pub async fn execute_tx(
        &self,
        signatures: Vec<Arc<UserSignature>>,
        tx: &Transaction,
        wait_for: Option<WaitForTx>,
    ) -> Result<TransactionEffects> {
        Ok(self
            .0
            .read()
            .await
            .execute_tx(
                &signatures
                    .into_iter()
                    .map(|s| s.0.clone())
                    .collect::<Vec<_>>(),
                &tx.0,
                wait_for,
            )
            .await?
            .into())
    }

    /// Returns whether the transaction for the given digest has been indexed
    /// on the node. This means that it can be queries by its digest and its
    /// effects will be usable for subsequent transactions. To check for
    /// full finalization, use `is_tx_finalized`.
    #[uniffi::method]
    pub async fn is_tx_indexed_on_node(&self, digest: &Digest) -> Result<bool> {
        Ok(self.0.read().await.is_tx_indexed_on_node(**digest).await?)
    }

    /// Returns whether the transaction for the given digest has been included
    /// in a checkpoint (finalized).
    #[uniffi::method]
    pub async fn is_tx_finalized(&self, digest: &Digest) -> Result<bool> {
        Ok(self.0.read().await.is_tx_finalized(**digest).await?)
    }

    /// Wait for the indexing or finalization of a transaction
    /// by its digest. An optional timeout can be provided, which, if
    /// exceeded, will return an error (default 60s).
    #[uniffi::method(default(timeout = None))]
    pub async fn wait_for_tx(
        &self,
        digest: &Digest,
        wait_for: WaitForTx,
        timeout: Option<Duration>,
    ) -> Result<()> {
        Ok(self
            .0
            .read()
            .await
            .wait_for_tx(**digest, wait_for, timeout)
            .await?)
    }
}

impl iota_sdk::transaction_builder::ClientMethods for GraphQLClient {
    type Error =
        <iota_sdk::graphql_client::Client as iota_sdk::transaction_builder::ClientMethods>::Error;
    type DryRunResult = iota_sdk::graphql_client::DryRunResult;

    async fn object(
        &self,
        object_id: iota_sdk::types::ObjectId,
        version: impl Into<Option<u64>>,
    ) -> Result<Option<iota_sdk::types::Object>, Self::Error> {
        iota_sdk::transaction_builder::ClientMethods::object(
            &*self.0.read().await,
            object_id,
            version,
        )
        .await
    }

    async fn objects(
        &self,
        type_tag: Option<iota_sdk::types::TypeTag>,
        owner: Option<iota_sdk::types::Address>,
        object_ids: Option<Vec<iota_sdk::types::ObjectId>>,
        ascending: bool,
        cursor: Option<String>,
        limit: Option<usize>,
    ) -> Result<Vec<iota_sdk::types::Object>, Self::Error> {
        iota_sdk::transaction_builder::ClientMethods::objects(
            &*self.0.read().await,
            type_tag,
            owner,
            object_ids,
            ascending,
            cursor,
            limit,
        )
        .await
    }

    async fn transaction(
        &self,
        digest: iota_sdk::types::Digest,
    ) -> Result<Option<iota_sdk::types::SignedTransaction>, Self::Error> {
        iota_sdk::transaction_builder::ClientMethods::transaction(&*self.0.read().await, digest)
            .await
    }

    async fn transaction_effects(
        &self,
        digest: iota_sdk::types::Digest,
    ) -> Result<Option<iota_sdk::types::TransactionEffects>, Self::Error> {
        iota_sdk::transaction_builder::ClientMethods::transaction_effects(
            &*self.0.read().await,
            digest,
        )
        .await
    }

    async fn reference_gas_price(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> Result<Option<u64>, Self::Error> {
        iota_sdk::transaction_builder::ClientMethods::reference_gas_price(
            &*self.0.read().await,
            epoch,
        )
        .await
    }

    async fn estimate_tx_budget(
        &self,
        tx: &iota_sdk::types::Transaction,
    ) -> Result<Option<u64>, Self::Error> {
        iota_sdk::transaction_builder::ClientMethods::estimate_tx_budget(&*self.0.read().await, tx)
            .await
    }

    async fn dry_run_tx(
        &self,
        tx: &iota_sdk::types::Transaction,
        skip_checks: bool,
    ) -> Result<Self::DryRunResult, Self::Error> {
        iota_sdk::transaction_builder::ClientMethods::dry_run_tx(
            &*self.0.read().await,
            tx,
            skip_checks,
        )
        .await
    }

    async fn execute_tx(
        &self,
        signatures: &[iota_sdk::types::UserSignature],
        tx: &iota_sdk::types::Transaction,
        wait_for: impl Into<Option<WaitForTx>>,
    ) -> Result<iota_sdk::types::TransactionEffects, Self::Error> {
        iota_sdk::transaction_builder::ClientMethods::execute_tx(
            &*self.0.read().await,
            signatures,
            tx,
            wait_for,
        )
        .await
    }

    async fn wait_for_tx(
        &self,
        digest: iota_sdk::types::Digest,
        wait_for: WaitForTx,
    ) -> Result<(), Self::Error> {
        iota_sdk::transaction_builder::ClientMethods::wait_for_tx(
            &*self.0.read().await,
            digest,
            wait_for,
        )
        .await
    }
}
