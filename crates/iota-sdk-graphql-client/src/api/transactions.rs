// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Transactions API implementation.

use std::time::Duration;

use base64ct::Encoding;
use cynic::{MutationBuilder, QueryBuilder};
use futures::Stream;
use iota_types::{
    Digest, SenderSignedTransaction, SignedTransaction, Transaction, TransactionEffects,
    UserSignature,
};

use crate::{
    Client, TransactionDataEffects,
    error::{Error, Kind, Result},
    pagination::{Direction, Page, PaginationFilter},
    query_types::{
        ExecuteTransactionQueryArgs, ExecuteTransactionQuery, TransactionBlockQueryArgs,
        TransactionBlockCheckpointQuery, TransactionBlockEffectsQuery,
        TransactionBlockIndexedQuery, TransactionBlockQuery, TransactionBlockWithEffectsQuery,
        TransactionBlocksEffectsQuery, TransactionBlocksQuery, TransactionBlocksQueryArgs,
        TransactionBlockFilter, TransactionBlocksWithEffectsQuery,
    },
    streams::stream_paginated_query,
};

/// Determines what to wait for after executing a transaction.
///
/// Users should almost always use [`WaitForTx::Finalized`] (the default).
/// The GraphQL client interacts with the indexer, not the fullnode directly.
/// Using [`WaitForTx::IndexedOnNode`] only guarantees the transaction is
/// indexed on the fullnode (meaning you can submit transactions that reference
/// objects created by this transaction), but subsequent queries using the
/// transaction ID can still fail until the transaction is indexed on the
/// indexer.
#[non_exhaustive]
#[derive(Default)]
pub enum WaitForTx {
    /// Indicates that the transaction effects will be usable in subsequent
    /// transactions (you can reference objects created by this transaction),
    /// and that the transaction itself is indexed on the fullnode.
    ///
    /// **Warning:** This does not guarantee the transaction is indexed on the
    /// indexer. Since the GraphQL client queries the indexer, subsequent
    /// queries with this transaction ID may still fail. Prefer
    /// [`WaitForTx::Finalized`] unless you have a specific reason to use this.
    IndexedOnNode,
    /// Indicates that the transaction has been included in a checkpoint, and
    /// all queries may include it.
    #[default]
    Finalized,
}

impl Client {
    /// Get a transaction by its digest.
    pub async fn transaction(&self, digest: Digest) -> Result<Option<SignedTransaction>> {
        let operation = TransactionBlockQuery::build(TransactionBlockQueryArgs {
            digest: digest.to_string(),
        });
        let response = self.run_query(&operation).await?;

        response
            .transaction_block
            .map(TryInto::try_into)
            .transpose()
    }

    /// Get a page of transactions based on the provided filters.
    pub async fn transactions(
        &self,
        filter: impl Into<Option<TransactionBlockFilter>>,
        pagination_filter: PaginationFilter,
    ) -> Result<Page<SignedTransaction>> {
        let pagination = self.pagination_filter(pagination_filter).await;

        let operation = TransactionBlocksQuery::build(TransactionBlocksQueryArgs {
            after: pagination.after,
            before: pagination.before,
            filter: filter.into(),
            first: pagination.first,
            last: pagination.last,
        });

        let response = self.run_query(&operation).await?;

        let txc = response.transaction_blocks;
        let page_info = txc.page_info;

        let transactions = txc
            .nodes
            .into_iter()
            .map(|n| n.try_into())
            .collect::<Result<Vec<_>>>()?;
        Ok(Page::new(page_info, transactions))
    }

    /// Get a transaction's effects by its digest.
    pub async fn transaction_effects(&self, digest: Digest) -> Result<Option<TransactionEffects>> {
        let operation = TransactionBlockEffectsQuery::build(TransactionBlockQueryArgs {
            digest: digest.to_string(),
        });
        let response = self.run_query(&operation).await?;

        response
            .transaction_block
            .map(TryInto::try_into)
            .transpose()
    }

    /// Get a page of transactions' effects based on the provided filters.
    pub async fn transactions_effects(
        &self,
        filter: impl Into<Option<TransactionBlockFilter>>,
        pagination_filter: PaginationFilter,
    ) -> Result<Page<TransactionEffects>> {
        let pagination = self.pagination_filter(pagination_filter).await;

        let operation = TransactionBlocksEffectsQuery::build(TransactionBlocksQueryArgs {
            after: pagination.after,
            before: pagination.before,
            filter: filter.into(),
            first: pagination.first,
            last: pagination.last,
        });

        let response = self.run_query(&operation).await?;

        let txc = response.transaction_blocks;
        let page_info = txc.page_info;

        let transactions = txc
            .nodes
            .into_iter()
            .map(|n| n.try_into())
            .collect::<Result<Vec<_>>>()?;
        Ok(Page::new(page_info, transactions))
    }

    /// Get a transaction's data and effects by its digest.
    pub async fn transaction_data_effects(
        &self,
        digest: Digest,
    ) -> Result<Option<TransactionDataEffects>> {
        let operation = TransactionBlockWithEffectsQuery::build(TransactionBlockQueryArgs {
            digest: digest.to_string(),
        });
        let response = self.run_query(&operation).await?;

        match response.transaction_block.map(|tx| (tx.bcs, tx.effects)) {
            Some((Some(bcs), Some(effects))) => {
                let bcs = base64ct::Base64::decode_vec(bcs.0.as_str())?;
                let effects = base64ct::Base64::decode_vec(effects.bcs.unwrap().0.as_str())?;
                let transaction: SenderSignedTransaction = bcs::from_bytes(&bcs)?;
                let effects: TransactionEffects = bcs::from_bytes(&effects)?;

                Ok(Some(TransactionDataEffects {
                    tx: transaction.0,
                    effects,
                }))
            }
            _ => Ok(None),
        }
    }

    /// Get a page of transactions' data and effects based on the provided
    /// filters.
    pub async fn transactions_data_effects(
        &self,
        filter: impl Into<Option<TransactionBlockFilter>>,
        pagination_filter: PaginationFilter,
    ) -> Result<Page<TransactionDataEffects>> {
        let pagination = self.pagination_filter(pagination_filter).await;

        let operation = TransactionBlocksWithEffectsQuery::build(TransactionBlocksQueryArgs {
            after: pagination.after,
            before: pagination.before,
            filter: filter.into(),
            first: pagination.first,
            last: pagination.last,
        });

        let response = self.run_query(&operation).await?;

        let txc = response.transaction_blocks;
        let page_info = txc.page_info;

        let transactions = {
            txc.nodes
                .into_iter()
                .map(|node| {
                    let (Some(bcs), Some(effects)) = (node.bcs, node.effects) else {
                        return Err(Error::empty_response_error());
                    };
                    let bcs = base64ct::Base64::decode_vec(bcs.0.as_str())?;
                    let effects =
                        base64ct::Base64::decode_vec(effects.bcs.as_ref().unwrap().0.as_str())?;
                    let transaction: SenderSignedTransaction = bcs::from_bytes(&bcs)?;
                    let effects: TransactionEffects = bcs::from_bytes(&effects)?;

                    Ok(TransactionDataEffects {
                        tx: transaction.0,
                        effects,
                    })
                })
                .collect::<Result<Vec<_>>>()?
        };

        Ok(Page::new(page_info, transactions))
    }

    /// Get a stream of transactions based on the (optional) transaction filter.
    pub fn transactions_stream(
        &self,
        filter: impl Into<Option<TransactionBlockFilter>>,
        streaming_direction: Direction,
    ) -> impl Stream<Item = Result<SignedTransaction>> + '_ {
        let filter = filter.into();
        stream_paginated_query(
            move |pag_filter| self.transactions(filter.clone(), pag_filter),
            streaming_direction,
        )
    }

    /// Get a stream of transactions' effects based on the (optional)
    /// transaction filter.
    pub fn transactions_effects_stream(
        &self,
        filter: impl Into<Option<TransactionBlockFilter>>,
        streaming_direction: Direction,
    ) -> impl Stream<Item = Result<TransactionEffects>> + '_ {
        let filter = filter.into();
        stream_paginated_query(
            move |pag_filter| self.transactions_effects(filter.clone(), pag_filter),
            streaming_direction,
        )
    }

    /// Execute a transaction.
    pub async fn execute_tx(
        &self,
        signatures: &[UserSignature],
        tx: &Transaction,
        wait_for: impl Into<Option<WaitForTx>>,
    ) -> Result<TransactionEffects> {
        let wait_for = wait_for.into();
        let operation = ExecuteTransactionQuery::build(ExecuteTransactionQueryArgs {
            signatures: signatures.iter().map(|s| s.to_base64()).collect(),
            tx_bytes: base64ct::Base64::encode_string(bcs::to_bytes(tx).unwrap().as_ref()),
        });

        let response = self.run_query(&operation).await?;

        let result = response.execute_transaction_block;
        let bcs = base64ct::Base64::decode_vec(result.effects.bcs.0.as_str())?;
        let effects: TransactionEffects = bcs::from_bytes(&bcs)?;

        if let Some(wait_for) = wait_for {
            self.wait_for_tx(tx.digest(), wait_for, None).await?;
        }

        Ok(effects)
    }

    /// Returns whether the transaction for the given digest has been indexed
    /// on the node. This means that it can be queried by its digest and its
    /// effects will be usable for subsequent transactions. To check for
    /// full finalization, use [`Self::is_tx_finalized`].
    pub async fn is_tx_indexed_on_node(&self, digest: Digest) -> Result<bool> {
        let operation = TransactionBlockIndexedQuery::build(TransactionBlockQueryArgs {
            digest: digest.to_string(),
        });
        Ok(self
            .run_query(&operation)
            .await?
            .is_transaction_indexed_on_node)
    }

    /// Returns whether the transaction for the given digest has been included
    /// in a checkpoint (finalized).
    pub async fn is_tx_finalized(&self, digest: Digest) -> Result<bool> {
        let operation = TransactionBlockCheckpointQuery::build(TransactionBlockQueryArgs {
            digest: digest.to_string(),
        });
        let response = self.run_query(&operation).await?;
        if let Some(block) = response.transaction_block
            && block
                .effects
                .as_ref()
                .and_then(|e| e.checkpoint.as_ref())
                .is_some()
        {
            return Ok(true);
        }
        Ok(false)
    }

    /// Wait for the indexing or finalization of a transaction
    /// by its digest. An optional timeout can be provided, which, if
    /// exceeded, will return an error (default 60s).
    pub async fn wait_for_tx(
        &self,
        digest: Digest,
        wait_for: WaitForTx,
        timeout: impl Into<Option<Duration>>,
    ) -> Result<()> {
        tokio::time::timeout(
            timeout.into().unwrap_or_else(|| Duration::from_secs(60)),
            async {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(100));
                loop {
                    interval.tick().await;
                    if match wait_for {
                        WaitForTx::IndexedOnNode => self.is_tx_indexed_on_node(digest).await?,
                        WaitForTx::Finalized => self.is_tx_finalized(digest).await?,
                    } {
                        break Ok(());
                    }
                }
            },
        )
        .await
        .map_err(|e| Error::from_error(Kind::Other, e))?
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        PaginationFilter, query_types::TransactionsFilter, test_utils::test_client,
    };

    #[tokio::test]
    async fn test_transaction_effects_query() {
        let client = test_client();
        let transactions = client
            .transactions(None, PaginationFilter::default())
            .await
            .unwrap();
        let tx_digest = transactions.data()[0].transaction.digest();
        let effects = client.transaction_effects(tx_digest).await.unwrap();
        assert!(
            effects.is_some(),
            "Transaction effects query failed for {} network.",
            client.rpc_server(),
        );
    }

    #[tokio::test]
    async fn test_transactions_effects_query() {
        let client = test_client();
        client
            .transactions_effects(None, PaginationFilter::default())
            .await
            .map_err(|e| {
                format!(
                    "Transactions effects query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
    }

    #[tokio::test]
    async fn test_transactions_query() {
        let client = test_client();
        let transactions = client
            .transactions(None, PaginationFilter::default())
            .await
            .map_err(|e| {
                format!(
                    "Transactions query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
        assert!(
            !transactions.is_empty(),
            "Transactions query returned no data for {} network",
            client.rpc_server()
        );
    }

    #[tokio::test]
    async fn test_transaction_data_effects() {
        let client = test_client();
        // Fetch a live digest rather than hard-coding one that can go stale.
        let transactions = client
            .transactions(None, PaginationFilter::default())
            .await
            .map_err(|e| {
                format!(
                    "Transactions query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
        let tx_digest = transactions.data()[0].transaction.digest();
        let result = client
            .transaction_data_effects(tx_digest)
            .await
            .map_err(|e| {
                format!(
                    "Transaction data effects query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
        assert!(
            result.is_some(),
            "Transaction data/effects query returned None for {} network",
            client.rpc_server(),
        );
    }

    #[tokio::test]
    async fn test_transactions_data_effects() {
        let client = test_client();
        // Fetch a live digest rather than hard-coding one that can go stale.
        let transactions = client
            .transactions(None, PaginationFilter::default())
            .await
            .map_err(|e| {
                format!(
                    "Transactions query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
        let tx_digest = transactions.data()[0].transaction.digest().to_string();
        let results = client
            .transactions_data_effects(
                TransactionsFilter {
                    transaction_ids: Some(vec![tx_digest]),
                    ..Default::default()
                },
                PaginationFilter::default(),
            )
            .await
            .map_err(|e| {
                format!(
                    "Transactions data effects query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
        assert!(
            !results.is_empty(),
            "Transactions data effects query returned no results for {} network",
            client.rpc_server(),
        );
    }
}
